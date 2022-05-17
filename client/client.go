package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"github.com/yaotthaha/IPCachePool/command"
	"github.com/yaotthaha/IPCachePool/pool"
	"github.com/yaotthaha/IPCachePool/tool"
	"io"
	"io/ioutil"
	"log"
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
	LogFile      *os.File
	Log          *log.Logger
	ReadTimeout  = 20 * time.Second
	WriteTimeout = 20 * time.Second
)

var (
	GlobalData pool.NetAddrSlice
	GlobalLock sync.RWMutex
	Shell      string
	ShellArg   string
)

func (cfg *Config) ClientRun(ctx context.Context) {
	if cfg.Log.File != "" {
		var err error
		LogFile, err = os.OpenFile(cfg.Log.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalln("open log file error:", err)
		}
		defer func(LogFile *os.File) {
			err := LogFile.Close()
			if err != nil {
				log.Fatalln("close log file error:", err)
			}
		}(LogFile)
		Log = log.New(LogFile, "", log.LstdFlags|log.Lshortfile)
	} else {
		Log = log.New(os.Stdout, "", log.LstdFlags|log.Lshortfile)
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
				CertKey, err := tls.X509KeyPair(V.Transport.TLS.Cert, V.Transport.TLS.Key)
				if err != nil {
					log.Fatalln("load cert key error:", err)
				}
				tlsCfg.Certificates = []tls.Certificate{CertKey}
				tlsCfg.RootCAs = x509.NewCertPool()
				for _, C := range V.Transport.TLS.CA {
					if C != nil && len(C) > 0 {
						tlsCfg.RootCAs.AppendCertsFromPEM(C)
					}
				}
				switch V.Transport.TLS.Verify {
				case -1:
					tlsCfg.InsecureSkipVerify = false
				case 0:
					tlsCfg.InsecureSkipVerify = true
				case 1:
					tlsCfg.InsecureSkipVerify = true
					tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
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
			var Do func() bool
			switch V.Transport.Type {
			case "tcp":
				Do = func() bool {
					var (
						Conn interface{}
						err  error
					)
					if tlsCfg == nil {
						Conn, err = net.Dial("tcp", net.JoinHostPort(V.Address, strconv.Itoa(int(V.Port))))
						if err != nil {
							log.Println(fmt.Sprintf("[%s] tcp connect to server error: %s", V.Name, err))
							return false
						}
					} else {
						Conn, err = tls.Dial("tcp", net.JoinHostPort(V.Address, strconv.Itoa(int(V.Port))), tlsCfg)
						if err != nil {
							log.Println(fmt.Sprintf("[%s] tcp(tls) connect to server error: %s", V.Name, err))
							return false
						}
					}
					GlobalLock.RLock()
					if !(len(GlobalData.IPv4) > 0 || len(GlobalData.IPv6) > 0 || len(GlobalData.CIDRv4) > 0 || len(GlobalData.CIDRv6) > 0) {
						GlobalLock.RUnlock()
						return false
					}
					Data := GlobalData
					GlobalLock.RUnlock()
					RawData, err := GenRaw(Data, time.Duration(V.TTL)*time.Second, V.PublicKey, V.ID)
					if err != nil {
						Log.Println(fmt.Sprintf("gen raw data error: %s", err))
						return false
					}
					switch Conn.(type) {
					case *tls.Conn:
						C := Conn.(*tls.Conn)
						defer func() {
							err := C.Close()
							if err != nil {
								Log.Println(fmt.Sprintf("[%s] tcp(tls) close conn error: %s", V.Name, err))
							}
						}()
						err := C.SetReadDeadline(time.Now().Add(ReadTimeout))
						if err != nil {
							Log.Println(fmt.Sprintf("[%s] tcp(tls) set read deadline error: %s", V.Name, err))
						}
						err = C.SetWriteDeadline(time.Now().Add(WriteTimeout))
						if err != nil {
							Log.Println(fmt.Sprintf("[%s] tcp(tls) set write deadline error: %s", V.Name, err))
						}
						_, err = C.Write(RawData)
						if err != nil {
							Log.Println(fmt.Sprintf("[%s] tcp(tls) write raw data error: %s", V.Name, err))
							return false
						}
						buf := bytes.Buffer{}
						_, err = io.Copy(&buf, C)
						if err != nil {
							Log.Println(fmt.Sprintf("[%s] tcp(tls) read raw data error: %s", V.Name, err))
							return false
						}
						switch string(buf.Bytes()) {
						case "fail":
							Log.Println(fmt.Sprintf("[%s] tcp(tls) server send a fail message", V.Name))
						case "success":
							Log.Println(fmt.Sprintf("[%s] tcp(tls) server send a success message", V.Name))
						default:
							Log.Println(fmt.Sprintf("[%s] tcp(tls) server send a unknown message: %s", V.Name, string(buf.Bytes())))
						}
					case net.Conn:
						C := Conn.(net.Conn)
						defer func() {
							err := C.Close()
							if err != nil {
								Log.Println(fmt.Sprintf("[%s] close conn error: %s", V.Name, err))
							}
						}()
						err := C.SetReadDeadline(time.Now().Add(ReadTimeout))
						if err != nil {
							Log.Println(fmt.Sprintf("[%s] tcp set read deadline error: %s", V.Name, err))
						}
						err = C.SetWriteDeadline(time.Now().Add(WriteTimeout))
						if err != nil {
							Log.Println(fmt.Sprintf("[%s] tcp set write deadline error: %s", V.Name, err))
						}
						_, err = C.Write(RawData)
						if err != nil {
							Log.Println(fmt.Sprintf("[%s] tcp write raw data error: %s", V.Name, err))
							return false
						}
						buf := bytes.Buffer{}
						_, err = io.Copy(&buf, C)
						if err != nil {
							Log.Println(fmt.Sprintf("[%s] tcp read raw data error: %s", V.Name, err))
							return false
						}
						switch string(buf.Bytes()) {
						case "fail":
							Log.Println(fmt.Sprintf("[%s] tcp server send a fail message", V.Name))
						case "success":
							Log.Println(fmt.Sprintf("[%s] tcp server send a success message", V.Name))
						default:
							Log.Println(fmt.Sprintf("[%s] tcp server send a unknown message: %s", V.Name, string(buf.Bytes())))
						}
					}
					return true
				}
			case "http":
				Do = func() bool {
					GlobalLock.RLock()
					if !(len(GlobalData.IPv4) > 0 || len(GlobalData.IPv6) > 0 || len(GlobalData.CIDRv4) > 0 || len(GlobalData.CIDRv6) > 0) {
						GlobalLock.RUnlock()
						return false
					}
					Data := GlobalData
					GlobalLock.RUnlock()
					RawData, err := GenRaw(Data, time.Duration(V.TTL)*time.Second, V.PublicKey, V.ID)
					if err != nil {
						Log.Println(fmt.Sprintf("gen raw data error: %s", err))
						return false
					}
					client := http.Client{
						Transport: &http.Transport{
							TLSClientConfig: tlsCfg,
						},
						CheckRedirect: nil,
						Jar:           nil,
						Timeout:       WriteTimeout,
					}
					req := http.Request{
						Method: http.MethodGet,
						URL: &url.URL{
							Scheme: func() string {
								if tlsCfg == nil {
									return "http"
								} else {
									return "https"
								}
							}(),
							Host: net.JoinHostPort(V.Address, strconv.Itoa(int(V.Port))),
							Path: V.Transport.HTTP.Path,
						},
						Body: ioutil.NopCloser(bytes.NewReader(RawData)),
						Host: func() string {
							if V.Transport.HTTP.Host != "" {
								return V.Transport.HTTP.Host
							} else if V.Transport.TLS.SNI != "" {
								return V.Transport.TLS.SNI
							} else {
								return V.Address
							}
						}(),
					}
					resp, err := client.Do(&req)
					if err != nil {
						Log.Println(fmt.Sprintf("[%s] http request error: %s", V.Name, err))
						return false
					}
					defer func(Body io.ReadCloser) {
						err := Body.Close()
						if err != nil {
							Log.Println(fmt.Sprintf("[%s] close conn error: %s", V.Name, err))
						}
					}(resp.Body)
					buf := bytes.Buffer{}
					_, err = io.Copy(&buf, resp.Body)
					if err != nil {
						Log.Println(fmt.Sprintf("[%s] http read response error: %s", V.Name, err))
						return false
					}
					switch string(buf.Bytes()) {
					case "fail":
						Log.Println(fmt.Sprintf("[%s] http server send a fail message", V.Name))
					case "success":
						Log.Println(fmt.Sprintf("[%s] http server send a success message", V.Name))
					default:
						Log.Println(fmt.Sprintf("[%s] http server send a unknown message: %s", V.Name, string(buf.Bytes())))
					}
					return true
				}
			case "quic":
				if tlsCfg == nil {
					Log.Fatalln("quic transport need tls config")
				} else {
					Do = func() bool {
						GlobalLock.RLock()
						if !(len(GlobalData.IPv4) > 0 || len(GlobalData.IPv6) > 0 || len(GlobalData.CIDRv4) > 0 || len(GlobalData.CIDRv6) > 0) {
							GlobalLock.RUnlock()
							return false
						}
						Data := GlobalData
						GlobalLock.RUnlock()
						RawData, err := GenRaw(Data, time.Duration(V.TTL)*time.Second, V.PublicKey, V.ID)
						if err != nil {
							Log.Println(fmt.Sprintf("gen raw data error: %s", err))
							return false
						}
						Conn, err := quic.DialAddr(net.JoinHostPort(V.Address, strconv.Itoa(int(V.Port))), tlsCfg, nil)
						if err != nil {
							Log.Println(fmt.Sprintf("[%s] quic dial error: %s", V.Name, err))
							return false
						}
						Stream, err := Conn.AcceptStream(context.Background())
						if err != nil {
							Log.Println(fmt.Sprintf("[%s] quic accept stream error: %s", V.Name, err))
							return false
						}
						defer func() {
							err := Stream.Close()
							if err != nil {
								Log.Println(fmt.Sprintf("[%s] quic stream close error: %s", V.Name, err))
							}
						}()
						err = Stream.SetReadDeadline(time.Now().Add(ReadTimeout))
						if err != nil {
							Log.Println(fmt.Sprintf("[%s] quic set read deadline error: %s", V.Name, err))
						}
						err = Stream.SetWriteDeadline(time.Now().Add(WriteTimeout))
						if err != nil {
							Log.Println(fmt.Sprintf("[%s] quic set write deadline error: %s", V.Name, err))
						}
						_, err = Stream.Write(RawData)
						if err != nil {
							Log.Println(fmt.Sprintf("[%s] quic write raw data error: %s", V.Name, err))
							return false
						}
						buf := bytes.Buffer{}
						_, err = io.Copy(&buf, Stream)
						if err != nil {
							Log.Println(fmt.Sprintf("[%s] quic read raw data error: %s", V.Name, err))
							return false
						}
						switch string(buf.Bytes()) {
						case "fail":
							Log.Println(fmt.Sprintf("[%s] quic server send a fail message", V.Name))
						case "success":
							Log.Println(fmt.Sprintf("[%s] quic server send a success message", V.Name))
						default:
							Log.Println(fmt.Sprintf("[%s] quic server send a unknown message: %s", V.Name, string(buf.Bytes())))
						}
						return true
					}
				}
			}
			firstChan := make(chan struct{}, 1)
			firstChan <- struct{}{}
			defer close(firstChan)
			for {
				select {
				case <-ctx.Done():
					return
				case <-firstChan:
					for !Do() {
						<-time.After(2 * time.Second)
						select {
						case <-ctx.Done():
							return
						default:
						}
					}
				case <-time.After(time.Duration(V.Interval) * time.Second):
					Do()
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
						stdout, stderr, err := command.Run(Shell, ShellArg, v.Script)
						if err != nil {
							if v.Fatal {
								Log.Fatalln(fmt.Sprintf("run script [%s] error: %s , stdout: %s, stderr: %s", v.Script, err, stdout, stderr))
							}
							if v.Return {
								Log.Println(fmt.Sprintf("run script [%s] error: %s , stdout: %s, stderr: %s", v.Script, err, stdout, stderr))
							}
						} else {
							if v.Return {
								Log.Println(fmt.Sprintf("run script [%s] success, stdout: %s", v.Script, stdout))
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

func GenRaw(d pool.NetAddrSlice, TTL time.Duration, pubKey string, ID string) ([]byte, error) {
	RealData := pool.Receive{
		Data: d,
		TTL:  TTL,
	}
	type RawDataStruct struct {
		Time     time.Time
		RealData pool.Receive
	}
	RawData := RawDataStruct{
		Time:     time.Now(),
		RealData: RealData,
	}
	buf := bytes.Buffer{}
	err := gob.NewEncoder(&buf).Encode(RawData)
	if err != nil {
		return nil, err
	}
	bufBytes := buf.Bytes()
	IDSha256 := tool.Sha256([]byte(ID))
	EncData, err := tool.ECCEncrypt(bufBytes, []byte(pubKey))
	if err != nil {
		return nil, err
	}
	Verify := tool.Sha256(bufBytes)
	Raw := IDSha256
	Raw = append(Raw, []byte("0xffffx0")...)
	Raw = append(Raw, Verify...)
	Raw = append(Raw, []byte("0xffffx0")...)
	Raw = append(Raw, EncData...)
	return Raw, nil
}
