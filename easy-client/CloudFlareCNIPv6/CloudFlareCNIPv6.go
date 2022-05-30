package CloudFlareCNIPv6

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

func HTTPDNSResolveFunc(Host string) (netip.Addr, error) {
	DNSIP := `223.5.5.5`
	HostReal, _, err := net.SplitHostPort(Host)
	if err != nil {
		if !strings.Contains(err.Error(), "missing port in address") {
			return netip.Addr{}, err
		} else {
			HostReal = Host
		}
	}
	QueryMap := make(map[string]string)
	QueryMap["name"] = HostReal
	QueryMap["short"] = "1"
	QueryMap["type"] = "aaaa"
	client := http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	req, _ := http.NewRequest(http.MethodGet, func() string {
		u := &url.URL{
			Scheme: "https",
			Host:   DNSIP,
			Path:   "/resolve",
			RawQuery: func() string {
				var Query string
				for k, v := range QueryMap {
					Query += k + "=" + v + "&"
				}
				return Query[:len(Query)-1]
			}(),
		}
		return u.String()
	}(), nil)
	var (
		respDNS *http.Response
		Num     = 0
	)
	for {
		respDNS, err = client.Do(req)
		if err != nil {
			Num++
		} else {
			break
		}
		if Num == 3 {
			break
		}
	}
	if err != nil {
		return netip.Addr{}, err
	}
	DataRaw, err := ioutil.ReadAll(respDNS.Body)
	if err != nil {
		return netip.Addr{}, err
	}
	var Data []string
	_ = json.Unmarshal(DataRaw, &Data)
	return netip.ParseAddr(Data[0])
}

func Get() (netip.Addr, error) {
	Domain := `cf-ns.com`
	IP, err := HTTPDNSResolveFunc(Domain)
	if err != nil {
		return netip.Addr{}, err
	}
	u := &url.URL{
		Scheme: "https",
		Host:   Domain,
		Path:   "/cdn-cgi/trace",
	}
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	req := &http.Request{
		Method:     http.MethodGet,
		URL:        u,
		Host:       Domain,
		RemoteAddr: net.JoinHostPort(IP.String(), "443"),
	}
	resp, err := client.Do(req)
	if err != nil {
		return netip.Addr{}, err
	}
	Data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return netip.Addr{}, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	DataSlice := bytes.Split(Data, []byte("\n"))
	return netip.ParseAddr(string(bytes.Split(DataSlice[2], []byte("="))[1]))
}
