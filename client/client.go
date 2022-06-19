package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/yaotthaha/IPCachePool/command"
	"github.com/yaotthaha/IPCachePool/logplus"
	"github.com/yaotthaha/IPCachePool/pool"
	"github.com/yaotthaha/IPCachePool/tool"
	"github.com/yaotthaha/IPCachePool/transport"
	"golang.org/x/net/http2"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	Log *logplus.LogPlus
)

var (
	GlobalData pool.NetAddrSlice
	GlobalLock sync.RWMutex
	Shell      string
	ShellArg   string
)

func (cfg *Config) ClientRun(ctx context.Context, GlobalLog *logplus.LogPlus) {
	Log = GlobalLog
	if cfg.Log.File != "" {
		var err error
		LogFile, err := os.OpenFile(cfg.Log.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			Log.Fatalln(logplus.Fatal, fmt.Sprintf("open log file error: %s", err))
		}
		defer func(LogFile *os.File) {
			Log.SetOutput(os.Stdout)
			err := LogFile.Close()
			if err != nil {
				Log.Fatalln(logplus.Fatal, fmt.Sprintf("close log file error: %s", err))
			}
		}(LogFile)
		Log.Printf(logplus.Info, "redirect log to %s\n", cfg.Log.File)
		Log.SetOutput(LogFile)
	}
	if cfg.Log.Debug {
		Log.Option.Debug = true
	}
	Shell = cfg.Shell
	ShellArg = cfg.ShellArg
	serverRunWG := sync.WaitGroup{}
	GlobalData = pool.NetAddrSlice{
		IPv4:   make([]netip.Addr, 0),
		IPv6:   make([]netip.Addr, 0),
		CIDRv4: make([]netip.Prefix, 0),
		CIDRv6: make([]netip.Prefix, 0),
	}
	GlobalLock = sync.RWMutex{}
	for _, v := range cfg.Servers {
		serverRunWG.Add(1)
		go func(V ConfigServer) {
			defer serverRunWG.Done()
			var tlsCfg *tls.Config
			if V.Transport.TLS.Enable {
				tlsCfg = &tls.Config{}
				tlsCfg.MinVersion = tls.VersionTLS12
				tlsCfg.MaxVersion = tls.VersionTLS13
				if (V.Transport.TLS.Cert != nil && len(V.Transport.TLS.Cert) > 0) && (V.Transport.TLS.Key != nil && len(V.Transport.TLS.Key) > 0) {
					CertKey, err := tls.X509KeyPair(V.Transport.TLS.Cert, V.Transport.TLS.Key)
					if err != nil {
						Log.Fatalln(logplus.Fatal, fmt.Sprintf("load cert key error: %s", err))
					}
					tlsCfg.Certificates = []tls.Certificate{CertKey}
				}
				if V.Transport.TLS.CA != nil && len(V.Transport.TLS.CA) > 0 {
					tlsCfg.RootCAs = x509.NewCertPool()
					for _, C := range V.Transport.TLS.CA {
						if C != nil && len(C) > 0 {
							tlsCfg.RootCAs.AppendCertsFromPEM(C)
						}
					}
				}
				if V.Transport.TLS.IgnoreVerify {
					tlsCfg.InsecureSkipVerify = true
				} else {
					tlsCfg.InsecureSkipVerify = false
				}
				if V.Transport.TLS.ALPN != "" {
					if len(V.Transport.TLS.ALPN) > 0 {
						tlsCfg.NextProtos = append(tlsCfg.NextProtos, V.Transport.TLS.ALPN)
					} else {
						tlsCfg.NextProtos = []string{V.Transport.TLS.ALPN}
					}
				}
				if V.Transport.TLS.SNI != "" {
					tlsCfg.ServerName = V.Transport.TLS.SNI
				}
			}
			Do := func(ctx context.Context) bool {
				GlobalLock.RLock()
				if !(len(GlobalData.IPv4) > 0 || len(GlobalData.IPv6) > 0 || len(GlobalData.CIDRv4) > 0 || len(GlobalData.CIDRv6) > 0) {
					GlobalLock.RUnlock()
					return false
				}
				Data := GlobalData
				GlobalLock.RUnlock()
				RawData, err := GenRaw(Data, time.Duration(V.TTL)*time.Second, V.PrivateKey, V.ClientID)
				if err != nil {
					Log.Println(logplus.Error, fmt.Sprintf("gen raw data error: %s", err))
					return false
				}
				client := http.Client{}
				client.Timeout = time.Duration(int(V.RequestTimeout)) * time.Second
				HTTPTr := make(map[int]interface{})
				HTTPTr[len(HTTPTr)] = &http.Transport{
					TLSClientConfig: tlsCfg,
				}
				if V.Transport.HTTP2.Enable {
					HTTPTr[len(HTTPTr)] = &http2.Transport{
						TLSClientConfig: tlsCfg,
					}
				}
				if V.Transport.HTTP3.Enable {
					HTTPTr[len(HTTPTr)] = &http3.RoundTripper{
						TLSClientConfig: tlsCfg,
					}
				}
				req := &http.Request{
					Method: http.MethodGet,
					URL: &url.URL{
						Scheme: func() string {
							if tlsCfg == nil {
								return "http"
							} else {
								return "https"
							}
						}(),
						Host: net.JoinHostPort(V.Transport.Address, strconv.Itoa(int(V.Transport.Port))),
						Path: V.Transport.HTTP.Path,
					},
					Body: ioutil.NopCloser(bytes.NewReader(RawData)),
					Host: func() string {
						if V.Transport.HTTP.Host != "" {
							return V.Transport.HTTP.Host
						} else if V.Transport.TLS.SNI != "" {
							return V.Transport.TLS.SNI
						} else {
							return V.Transport.Address
						}
					}(),
				}
				req.Header.Add("Content-Type", "application/json")
				req = req.WithContext(ctx)
				var resp *http.Response
				p := 0
				retry := 2
				for {
					BreakTag := false
					select {
					case <-ctx.Done():
						return false
					default:
						l := p % len(HTTPTr)
						t := HTTPTr[len(HTTPTr)-l-1]
						switch t.(type) {
						case *http.Transport:
							if r := p / len(HTTPTr); r == 0 {
								Log.Println(logplus.Debug, fmt.Sprintf("[%s] use http client", V.Name))
							} else {
								Log.Println(logplus.Debug, fmt.Sprintf("[%s] retry %s, use http client", V.Name, strconv.Itoa(r)))
							}
							client.Transport = t.(*http.Transport)
						case *http2.Transport:
							if r := p / len(HTTPTr); r == 0 {
								Log.Println(logplus.Debug, fmt.Sprintf("[%s] use http2 client", V.Name))
							} else {
								Log.Println(logplus.Debug, fmt.Sprintf("[%s] retry %s, use http2 client", V.Name, strconv.Itoa(r)))
							}
							client.Transport = t.(*http2.Transport)
						case *http3.RoundTripper:
							if r := p / len(HTTPTr); r == 0 {
								Log.Println(logplus.Debug, fmt.Sprintf("[%s] use http3 client", V.Name))
							} else {
								Log.Println(logplus.Debug, fmt.Sprintf("[%s] retry %s, use http3 client", V.Name, strconv.Itoa(r)))
							}
							client.Transport = t.(*http3.RoundTripper)
						}
						var err error
						resp, err = client.Do(req)
						if err != nil {
							Log.Println(logplus.Error, fmt.Sprintf("[%s] http request error: %s", V.Name, err))
							if p == len(HTTPTr)*retry-1 {
								return false
							} else {
								p++
								continue
							}
						}
						BreakTag = true
					}
					if BreakTag {
						break
					}
				}
				defer func(Body io.ReadCloser) {
					err := Body.Close()
					if err != nil {
						Log.Println(logplus.Error, fmt.Sprintf("[%s] close conn error: %s", V.Name, err))
					}
				}(resp.Body)
				buf := bytes.Buffer{}
				_, err = io.Copy(&buf, resp.Body)
				if err != nil {
					Log.Println(logplus.Error, fmt.Sprintf("[%s] http read response error: %s", V.Name, err))
					return false
				}
				switch string(buf.Bytes()) {
				case "fail":
					Log.Println(logplus.Error, fmt.Sprintf("[%s] http server send a fail message", V.Name))
				case "success":
					Log.Println(logplus.Debug, fmt.Sprintf("[%s] http server send a success message", V.Name))
				default:
					Log.Println(logplus.Warning, fmt.Sprintf("[%s] http server send a unknown message: %s", V.Name, string(buf.Bytes())))
				}
				return true
			}
			firstChan := make(chan struct{}, 1)
			firstChan <- struct{}{}
			defer close(firstChan)
			for {
				select {
				case <-ctx.Done():
					return
				case <-firstChan:
					for !Do(ctx) {
						<-time.After(2 * time.Second)
					}
				case <-time.After(time.Duration(V.Interval) * time.Second):
					Do(ctx)
				}
			}
		}(v)
	}
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverRunWG.Wait()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		IntervalSlice := func() []uint {
			S := make([]uint, 0)
			for _, F := range cfg.Servers {
				S = append(S, F.Interval)
			}
			return S
		}()
		sort.Slice(IntervalSlice, func(i, j int) bool {
			if IntervalSlice[i] < IntervalSlice[j] {
				return false
			} else {
				return true
			}
		})
		Interval := IntervalSlice[0]
		for {
			select {
			case <-ctx.Done():
				return
			default:
				RvChan := make(chan []byte, 1024)
				T := pool.NetAddrSlice{
					IPv4:   make([]netip.Addr, 0),
					IPv6:   make([]netip.Addr, 0),
					CIDRv4: make([]netip.Prefix, 0),
					CIDRv6: make([]netip.Prefix, 0),
				}
				TLock := sync.Mutex{}
				c, cFunc := context.WithCancel(context.Background())
				go func() {
					TLock.Lock()
					defer TLock.Unlock()
					for {
						select {
						case d := <-RvChan:
							dStr := strings.Trim(string(d), "\n")
							dSlice := strings.Split(dStr, "|")
							for _, q := range dSlice {
								if q != "" {
									IP, err := netip.ParseAddr(q)
									if err != nil {
										CIDR, err := netip.ParsePrefix(q)
										if err != nil {
											continue
										} else {
											if CIDR.Addr().Is4() {
												T.CIDRv4 = append(T.CIDRv4, CIDR)
											} else if CIDR.Addr().Is6() {
												T.CIDRv6 = append(T.CIDRv6, CIDR)
											}
										}
									} else {
										if IP.Is4() {
											T.IPv4 = append(T.IPv4, IP)
										} else if IP.Is6() {
											T.IPv6 = append(T.IPv6, IP)
										}
									}
								}
							}
						default:
							select {
							case <-c.Done():
								if len(RvChan) > 0 {
									continue
								} else {
									return
								}
							default:
								continue
							}
						}
					}
				}()
				w := sync.WaitGroup{}
				for _, v := range cfg.Script {
					w.Add(1)
					go func(v ConfigParseScriptBasic) {
						defer w.Done()
						ShellReal := Shell
						if v.Shell != "" {
							ShellReal = v.Shell
						}
						ShellArgReal := ShellArg
						if v.ShellArg != "" {
							ShellArgReal = v.ShellArg
						}
						stdout, stderr, err := command.Run(ShellReal, ShellArgReal, v.Script)
						ScriptShow := func() string {
							if v.Script == "" {
								return ShellReal + " " + ShellArgReal
							} else {
								return v.Script
							}
						}()
						if err != nil {
							if v.Fatal {
								Log.Fatalln(logplus.Fatal, fmt.Sprintf("run script [%s] error: %s , stdout: %s, stderr: %s", ScriptShow, err, stdout, stderr))
							}
							if v.Return {
								Log.Println(logplus.Error, fmt.Sprintf("run script [%s] error: %s , stdout: %s, stderr: %s", ScriptShow, err, stdout, stderr))
							}
						} else {
							if v.Return {
								Log.Println(logplus.Info, fmt.Sprintf("run script [%s] success, stdout: %s", ScriptShow, stdout))
							}
						}
						RvChan <- stdout
					}(v)
				}
				w.Wait()
				cFunc()
				TLock.Lock()
				TLock.Unlock()
				close(RvChan)
				if len(T.IPv4) > 0 || len(T.IPv6) > 0 || len(T.CIDRv4) > 0 || len(T.CIDRv6) > 0 {
					GlobalLock.Lock()
					GlobalData = T
					GlobalLock.Unlock()
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Duration(Interval) * time.Second):
				}
			}
		}
	}()
	wg.Wait()
}

func GenRaw(d pool.NetAddrSlice, TTL time.Duration, priKey string, ID string) ([]byte, error) {
	RealData := transport.Transport{
		ID:   ID,
		Time: time.Now().Format(time.RFC3339Nano),
		Data: struct {
			IPv4   []netip.Addr   `json:"ipv4"`
			IPv6   []netip.Addr   `json:"ipv6"`
			CIDRv4 []netip.Prefix `json:"cidrv4"`
			CIDRv6 []netip.Prefix `json:"cidrv6"`
		}{
			IPv4:   d.IPv4,
			IPv6:   d.IPv6,
			CIDRv4: d.CIDRv4,
			CIDRv6: d.CIDRv6,
		},
		TTL: int64(TTL.Seconds()),
	}
	Verify, err := tool.ECCSign([]byte(RealData.Time), []byte(priKey))
	if err != nil {
		return nil, err
	}
	RealData.Verify = string(Verify)
	return json.Marshal(RealData)
}
