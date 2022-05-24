package easy_client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/yaotthaha/IPCachePool/easy-client/OoklaGetIP"
	"github.com/yaotthaha/logplus"
	"golang.org/x/net/http2"
	"io/ioutil"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var (
	Log *logplus.LogPlus
)

func (cfg *Config) EasyClientRun(GlobalLog *logplus.LogPlus) {
	Log = GlobalLog
	var tlsConfig *tls.Config
	if cfg.Server.TLS.Enable {
		tlsConfig = &tls.Config{}
		if cfg.Server.TLS.IgnoreVerify {
			tlsConfig.InsecureSkipVerify = true
		}
		if cfg.Server.TLS.CA != nil {
			tlsConfig.RootCAs = x509.NewCertPool()
			for _, v := range cfg.Server.TLS.CA {
				if ok := tlsConfig.RootCAs.AppendCertsFromPEM(v); !ok {
					Log.Fatalln(logplus.Fatal, "load ca fail")
					return
				}
			}
		}
		if len(cfg.Server.TLS.Cert) > 0 && len(cfg.Server.TLS.Key) > 0 {
			CertKey, err := tls.X509KeyPair(cfg.Server.TLS.Cert, cfg.Server.TLS.Key)
			if err != nil {
				Log.Fatalln(logplus.Fatal, err)
				return
			}
			tlsConfig.Certificates = []tls.Certificate{CertKey}
		}
		if cfg.Server.TLS.ALPN != "" {
			if tlsConfig.NextProtos == nil || len(tlsConfig.NextProtos) == 0 {
				tlsConfig.NextProtos = []string{cfg.Server.TLS.ALPN}
			} else {
				tlsConfig.NextProtos = append(tlsConfig.NextProtos, cfg.Server.TLS.ALPN)
			}
		}
		if cfg.Server.TLS.SNI != "" {
			tlsConfig.ServerName = cfg.Server.TLS.SNI
		}
	}
	Result := make([]string, 0)
	if len(cfg.Script) > 0 {
		for _, v := range cfg.Script {
			output, err := exec.Command(v).Output()
			if err != nil {
				Log.Println(logplus.Error, err)
				continue
			}
			r := strings.Trim(string(output), "\r\n")
			r = strings.Trim(r, "\n")
			g := strings.Split(r, "|")
			if len(g) > 0 {
				for _, i := range g {
					if IP, err := netip.ParseAddr(i); err == nil {
						Result = append(Result, IP.String())
						continue
					}
					if CIDR, err := netip.ParsePrefix(i); err == nil {
						Result = append(Result, CIDR.String())
						continue
					}
				}
			}
		}
	}
	IPs, err := OoklaGetIP.OoklaGetAllIP()
	if err != nil {
		Log.Println(logplus.Warning, err)
	} else {
		for _, v := range IPs {
			Result = append(Result, v.String())
		}
	}
	ResultMap := make(map[string]int)
	for _, v := range Result {
		ResultMap[v]++
	}
	Result = make([]string, 0)
	for k := range ResultMap {
		Result = append(Result, k)
	}
	if len(Result) == 0 {
		Log.Fatalln(logplus.Fatal, "no ip/cidr found")
		return
	}
	data, err := json.Marshal(Result)
	if err != nil {
		Log.Fatalln(logplus.Fatal, err)
		return
	}
	Log.Println(logplus.Info, "ip/cidr:", Result)
	cfg.send(data, tlsConfig)
}

func (cfg *Config) send(data []byte, tlsConfig *tls.Config) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	switch {
	case cfg.Server.HTTP2.Enable:
		client.Transport = &http2.Transport{
			TLSClientConfig: tlsConfig,
		}
	case cfg.Server.HTTP3.Enable:
		client.Transport = &http3.RoundTripper{
			TLSClientConfig: tlsConfig,
		}
	default:
		client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}
	req := &http.Request{
		Method: http.MethodGet,
		URL: &url.URL{
			Scheme: func() string {
				if tlsConfig != nil {
					return "https"
				} else {
					return "http"
				}
			}(),
			Host: net.JoinHostPort(cfg.Server.Address, strconv.Itoa(int(cfg.Server.Port))),
			Path: cfg.Server.HTTP.Path,
		},
		Header: func() http.Header {
			if cfg.Server.HTTP.Header != nil {
				H := make(http.Header)
				for k, v := range cfg.Server.HTTP.Header {
					H.Set(k, v)
				}
				return H
			} else {
				return http.Header{}
			}
		}(),
		Host: func() string {
			if cfg.Server.HTTP.Host != "" {
				return cfg.Server.HTTP.Host
			} else if cfg.Server.TLS.SNI != "" {
				return cfg.Server.TLS.SNI
			} else {
				return cfg.Server.Address
			}
		}(),
	}
	req.Body = ioutil.NopCloser(bytes.NewReader(data))
	resp, err := client.Do(req)
	if err != nil {
		Log.Println(logplus.Error, err)
		return
	}
	if resp.StatusCode == 200 {
		Log.Println(logplus.Info, "send success")
	} else {
		Log.Println(logplus.Error, fmt.Sprintf("send fail: %s %s", strconv.Itoa(resp.StatusCode), resp.Status))
	}
}
