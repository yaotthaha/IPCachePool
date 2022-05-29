package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/yaotthaha/IPCachePool/command"
	"github.com/yaotthaha/IPCachePool/ipset"
	"github.com/yaotthaha/IPCachePool/logplus"
	"github.com/yaotthaha/IPCachePool/netstat"
	"github.com/yaotthaha/IPCachePool/pool"
	"github.com/yaotthaha/IPCachePool/tool"
	"github.com/yaotthaha/cachemap"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	Log           *logplus.LogPlus
	ReadTimeout   = 30 * time.Second
	WriteTimeout  = 30 * time.Second
	VerifyTimeout = 30 * time.Second
)

var (
	ClientMap       map[string]ConfigParseClient
	ClientCacheMap  map[string]cachemap.CacheMap
	ClientLock      sync.Mutex
	EasyCacheMap    cachemap.CacheMap
	Netstat         cachemap.CacheMap
	NetstatLock     sync.RWMutex
	EasyCheckFunc   func(address interface{}, interval, retryInterval uint)
	GlobalCacheMap  pool.NetAddrSlice
	GlobalChan      chan struct{}
	RequestCacheMap cachemap.CacheMap
	CommandSlice    ConfigParseScript
	IPSet           ConfigParseIPSet
	Shell           string
	ShellArg        string
	IPSetSupport    bool
)

func (cfg *Config) ServerRun(ctx context.Context, GlobalLog *logplus.LogPlus) {
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
				Log.Fatalf(logplus.Fatal, "close log file error: %s\n", err)
			}
		}(LogFile)
		Log.Printf(logplus.Info, "redirect log to %s\n", cfg.Log.File)
		Log.SetOutput(LogFile)
	}
	if cfg.Log.Debug {
		Log.Option.Debug = true
	}
	ClientMap = make(map[string]ConfigParseClient)
	ClientCacheMap = make(map[string]cachemap.CacheMap)
	for _, v := range cfg.Clients {
		IDSha256 := string(tool.Sha256([]byte(v.ClientID)))
		ClientMap[IDSha256] = v
		ClientCacheMap[IDSha256] = cachemap.NewCacheMap()
	}
	if cfg.IPSet.Enable {
		err := ipset.Check()
		if err != nil {
			Log.Println(logplus.Warning, fmt.Sprintf("ipset not support: %s", err))
			IPSetSupport = false
		} else {
			d4 := 0
			d6 := 0
			if cfg.IPSet.Name4 != "" {
				err = ipset.Create(cfg.IPSet.Name4, "4")
				if err != nil && !strings.Contains(err.Error(), "exist") {
					Log.Fatalln(logplus.Fatal, fmt.Sprintf("ipset [%s] create error: %s", cfg.IPSet.Name4, err))
				} else {
					Log.Println(logplus.Info, fmt.Sprintf("ipset [%s] create success", cfg.IPSet.Name4))
					d4++
				}
			}
			if cfg.IPSet.Name6 != "" {
				err = ipset.Create(cfg.IPSet.Name6, "6")
				if err != nil && !strings.Contains(err.Error(), "exist") {
					Log.Fatalln(logplus.Fatal, fmt.Sprintf("ipset [%s] create error: %s", cfg.IPSet.Name6, err))
				} else {
					Log.Println(logplus.Info, fmt.Sprintf("ipset [%s] create success", cfg.IPSet.Name6))
					d6++
				}
			}
			if d4+d6 == 0 {
				IPSetSupport = false
				Log.Println(logplus.Warning, "ipset not support")
				if d4 != 0 {
					err := ipset.Destroy(cfg.IPSet.Name4, "4")
					if err == nil {
						Log.Println(logplus.Info, fmt.Sprintf("ipset [%s] destroy success", cfg.IPSet.Name4))
					} else {
						Log.Println(logplus.Error, fmt.Sprintf("ipset [%s] destroy error: %s", cfg.IPSet.Name4, err))
					}
				}
				if d6 != 0 {
					err = ipset.Destroy(cfg.IPSet.Name6, "6")
					if err == nil {
						Log.Println(logplus.Info, fmt.Sprintf("ipset [%s] destroy success", cfg.IPSet.Name6))
					} else {
						Log.Println(logplus.Error, fmt.Sprintf("ipset [%s] destroy error: %s", cfg.IPSet.Name6, err))
					}
				}
			} else {
				IPSetSupport = true
			}
		}
	} else {
		IPSetSupport = false
	}
	IPSet = cfg.IPSet
	Shell = cfg.Shell
	ShellArg = cfg.ShellArg
	if cfg.Scripts.Pre != nil && len(cfg.Scripts.Pre) > 0 {
		for _, v := range cfg.Scripts.Pre {
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
					Log.Fatalln(logplus.Fatal, fmt.Sprintf("run pre script [%s] error: %s , stdout: %s, stderr: %s", ScriptShow, err, stdout, stderr))
				}
				if v.Return {
					Log.Println(logplus.Error, fmt.Sprintf("run pre script [%s] error: %s , stdout: %s, stderr: %s", ScriptShow, err, stdout, stderr))
				} else {
					Log.Println(logplus.Info, fmt.Sprintf("run pre script %s", ScriptShow))
				}
			} else {
				if v.Return {
					Log.Println(logplus.Info, fmt.Sprintf("run pre script [%s] success, stdout: %s", ScriptShow, stdout))
				} else {
					Log.Println(logplus.Info, fmt.Sprintf("run pre script %s", ScriptShow))
				}
			}
		}
	}
	ClientLock = sync.Mutex{}
	GlobalCacheMap = pool.NetAddrSlice{
		IPv4:   make([]netip.Addr, 0),
		IPv6:   make([]netip.Addr, 0),
		CIDRv4: make([]netip.Prefix, 0),
		CIDRv6: make([]netip.Prefix, 0),
	}
	RequestCacheMap = cachemap.NewCacheMap()
	GlobalChan = make(chan struct{}, 1024)
	defer close(GlobalChan)
	CommandSlice = cfg.Scripts
	var tlsCfg *tls.Config
	if cfg.Transport.TLS.Enable {
		tlsCfg = &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
			Certificates: []tls.Certificate{
				func() tls.Certificate {
					CertKey, err := tls.X509KeyPair(cfg.Transport.TLS.Cert, cfg.Transport.TLS.Key)
					if err != nil {
						log.Fatalln("load cert error:", err)
					}
					return CertKey
				}(),
			},
			ClientCAs: func() *x509.CertPool {
				CertPool := x509.NewCertPool()
				d := 0
				for _, C := range cfg.Transport.TLS.CA {
					if C != nil && len(C) > 0 {
						CertPool.AppendCertsFromPEM(C)
						d++
					}
				}
				if d != 0 {
					return CertPool
				} else {
					return nil
				}
			}(),
			ClientAuth: func() tls.ClientAuthType {
				switch cfg.Transport.TLS.RequireClientCert {
				case 0:
					return tls.NoClientCert
				case 1:
					return tls.VerifyClientCertIfGiven
				case 2:
					return tls.RequireAnyClientCert
				case 3:
					return tls.RequireAndVerifyClientCert
				default:
					return tls.NoClientCert
				}
			}(),
			InsecureSkipVerify: cfg.Transport.TLS.IgnoreVerify,
		}
		if tlsCfg.NextProtos != nil && len(tlsCfg.NextProtos) > 0 {
			tlsCfg.NextProtos = append(tlsCfg.NextProtos, cfg.Transport.TLS.ALPN)
		} else {
			tlsCfg.NextProtos = []string{cfg.Transport.TLS.ALPN}
		}
	}
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		globalRun(ctx)
	}()
	if cfg.Transport.Easy.AutoCheck.Enable {
		EasyCacheMap = cachemap.NewCacheMap()
		Netstat = cachemap.NewCacheMap()
		NetstatLock = sync.RWMutex{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(5 * time.Second):
					Temp, err := netstat.GetAll()
					if err != nil {
						NetstatLock.Unlock()
						continue
					}
					NetstatLock.Lock()
					w := sync.WaitGroup{}
					for _, v := range Temp {
						w.Add(1)
						go func(v netip.Addr) {
							defer w.Done()
							if Netstat.SetTTL(v, 10*time.Second, true) != nil {
								_ = Netstat.Add(v, nil, 10*time.Second, nil)
							}
						}(v.RemoteIP)
					}
					w.Wait()
					NetstatLock.Unlock()
				}
			}
		}()
		EasyCheckFunc = func(address interface{}, interval, retryInterval uint) {
			CheckFunc := func() bool {
				NetstatLock.RLock()
				_, err := Netstat.Get(address)
				NetstatLock.RUnlock()
				if err != nil {
					return false
				}
				return true
			}
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Duration(interval) * time.Second):
					if CheckFunc() {
						continue
					} else {
						for {
							Break := false
							select {
							case <-ctx.Done():
								return
							case <-time.After(time.Duration(retryInterval) * time.Second):
								if CheckFunc() {
									Break = true
									break
								} else {
									_ = EasyCacheMap.SetTTL(address, 1, true)
									return
								}
							}
							if Break {
								break
							}
						}
					}
				}
			}
		}
	}
	HTTPHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverHandler(w, r, cfg.Transport)
	})
	if cfg.Transport.HTTP3.Enable && cfg.Transport.HTTP3.Only {
		wg.Add(1)
		go func() {
			defer wg.Done()
			HTTP3ServerRun(tlsCfg, ctx, cfg.Transport, HTTPHandler)
		}()
	} else if cfg.Transport.HTTP3.Enable && !cfg.Transport.HTTP3.Only {
		wg.Add(1)
		go func() {
			defer wg.Done()
			HTTPServerRun(tlsCfg, ctx, cfg.Transport, HTTPHandler)
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			HTTP3ServerRun(tlsCfg, ctx, cfg.Transport, HTTPHandler)
		}()
	} else {
		wg.Add(1)
		go func() {
			defer wg.Done()
			HTTPServerRun(tlsCfg, ctx, cfg.Transport, HTTPHandler)
		}()
	}
	wg.Wait()
	Log.Println(logplus.Warning, "server close")
	if cfg.Scripts.Post != nil && len(cfg.Scripts.Post) > 0 {
		for _, v := range cfg.Scripts.Post {
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
					Log.Fatalln(logplus.Fatal, fmt.Sprintf("run post script [%s] error: %s , stdout: %s, stderr: %s", ScriptShow, err, stdout, stderr))
				}
				if v.Return {
					Log.Println(logplus.Error, fmt.Sprintf("run post script [%s] error: %s , stdout: %s, stderr: %s", ScriptShow, err, stdout, stderr))
				} else {
					Log.Println(logplus.Info, fmt.Sprintf("run post script %s", ScriptShow))
				}
			} else {
				if v.Return {
					Log.Println(logplus.Info, fmt.Sprintf("run post script [%s] success, stdout: %s", ScriptShow, stdout))
				} else {
					Log.Println(logplus.Info, fmt.Sprintf("run post script %s", ScriptShow))
				}
			}
		}
	}
	if IPSetSupport {
		if IPSet.Name4 != "" {
			err := ipset.Destroy(cfg.IPSet.Name4, "4")
			if err != nil {
				Log.Println(logplus.Error, fmt.Sprintf("ipset [%s] destroy fail: %s", cfg.IPSet.Name4, err))
			} else {
				Log.Println(logplus.Info, fmt.Sprintf("ipset [%s] destroy success", cfg.IPSet.Name4))
			}
		}
		if IPSet.Name6 != "" {
			err := ipset.Destroy(cfg.IPSet.Name6, "6")
			if err != nil {
				Log.Println(logplus.Error, fmt.Sprintf("ipset [%s] destroy fail: %s", cfg.IPSet.Name6, err))
			} else {
				Log.Println(logplus.Info, fmt.Sprintf("ipset [%s] destroy success", cfg.IPSet.Name6))
			}
		}
	}
	Log.Println(logplus.Info, "server exit")
}

func HTTPServerRun(tlsCfg *tls.Config, ctx context.Context, cfg ConfigTransport, handlerFunc http.HandlerFunc) {
	ListenAddr := net.JoinHostPort(cfg.Listen, strconv.Itoa(int(cfg.Port)))
	Log.Println(logplus.Info, fmt.Sprintf("listen on %s http server", ListenAddr))
	server := &http.Server{
		Addr:         ListenAddr,
		Handler:      http.Handler(handlerFunc),
		ReadTimeout:  ReadTimeout,
		WriteTimeout: WriteTimeout,
	}
	if tlsCfg != nil {
		server.TLSConfig = tlsCfg
	}
	go func() {
		<-ctx.Done()
		err := server.Shutdown(context.Background())
		if err != nil {
			Log.Println(logplus.Error, fmt.Sprintf("http server shutdown error: %s", err))
		}
	}()
	var err error
	if tlsCfg != nil {
		err = server.ListenAndServeTLS("", "")
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		Log.Fatalln(logplus.Fatal, fmt.Sprintf("http server close err: %s", err))
	}
}

func HTTP3ServerRun(tlsCfg *tls.Config, ctx context.Context, cfg ConfigTransport, handlerFunc http.HandlerFunc) {
	ListenAddr := net.JoinHostPort(cfg.Listen, strconv.Itoa(int(cfg.Port)))
	Log.Printf(logplus.Info, fmt.Sprintf("listen on %s http3 server", ListenAddr))
	server := &http3.Server{
		Server: &http.Server{
			Addr:         ListenAddr,
			Handler:      http.Handler(handlerFunc),
			ReadTimeout:  ReadTimeout,
			WriteTimeout: WriteTimeout,
		},
		QuicConfig: &quic.Config{},
	}
	if tlsCfg != nil {
		server.TLSConfig = tlsCfg
	}
	go func() {
		<-ctx.Done()
		err := server.Shutdown(context.Background())
		if err != nil {
			Log.Printf(logplus.Error, "http3 server shutdown error: %s\n", err)
		}
	}()
	var err error
	if tlsCfg != nil {
		err = server.ListenAndServeTLS("", "")
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		Log.Fatalln(logplus.Fatal, fmt.Sprintf("http3 server close err: %s", err))
	}
}

func serverHandler(w http.ResponseWriter, r *http.Request, cfg ConfigTransport) {
	RemoteAddr := func() string {
		if cfg.HTTP.RealIPHeader != "" {
			if r.Header.Get(cfg.HTTP.RealIPHeader) != "" {
				return r.Header.Get(cfg.HTTP.RealIPHeader)
			} else {
				addr, _, _ := net.SplitHostPort(r.RemoteAddr)
				return addr
			}
		} else {
			addr, _, _ := net.SplitHostPort(r.RemoteAddr)
			return addr
		}
	}()
	Log.Printf(logplus.Debug, "accept %s\n", RemoteAddr)
	switch r.URL.Path {
	case cfg.HTTP.Path:
		buf, err := ioutil.ReadAll(r.Body)
		if err != nil {
			Log.Println(logplus.Debug, fmt.Sprintf("%s read error: %s", RemoteAddr, err))
			return
		}
		Log.Println(logplus.Debug, fmt.Sprintf("%s read success", RemoteAddr))
		rt := Handler(buf)
		if rt != nil && len(rt) > 0 {
			_, err := w.Write(rt)
			if err != nil {
				Log.Println(logplus.Debug, fmt.Sprintf("%s write error: %s", RemoteAddr, err))
			}
		}
	case cfg.Easy.Path:
		if !cfg.Easy.Enable {
			Log.Println(logplus.Debug, fmt.Sprintf("%s path not match: %s", RemoteAddr, r.URL.Path))
			return
		}
		if r.Header.Get("Auth-Key") != cfg.Easy.Key {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		buf, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer func(Body io.ReadCloser) {
			_ = Body.Close()
		}(r.Body)
		var Addresses []string
		err = json.Unmarshal(buf, &Addresses)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		Log.Println(logplus.Debug, fmt.Sprintf("%s read success", RemoteAddr))
		if len(Addresses) <= 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for _, v := range Addresses {
			_, err := netip.ParseAddr(v)
			if err != nil {
				_, err = netip.ParsePrefix(v)
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
			}
		}
		EasyHandler(cfg.Easy, Addresses)
		w.WriteHeader(http.StatusOK)
		return
	default:
		Log.Println(logplus.Debug, fmt.Sprintf("%s path not match: %s", RemoteAddr, r.URL.Path))
		return
	}
}

func Handler(buf []byte) []byte {
	if buf == nil {
		return []byte("fail")
	}
	if len(buf) <= 0 {
		return []byte("fail")
	}
	bufBase64Dec, err := tool.Base64Decode(buf)
	if err != nil {
		return []byte("fail")
	}
	type RawDataStruct struct {
		IDSha256    []byte
		Verify      string
		Time        int64
		EncryptData []byte
	}
	var RawData RawDataStruct
	err = gob.NewDecoder(bytes.NewReader(bufBase64Dec)).Decode(&RawData)
	if err != nil {
		return []byte("fail")
	}
	TimeRv := time.Unix(RawData.Time, 0)
	IDSha256 := RawData.IDSha256
	EncryptData := RawData.EncryptData
	Verify := tool.Base64Encode(tool.Sha256(append(IDSha256, append([]byte(strconv.FormatInt(RawData.Time, 10)), EncryptData...)...)))
	if !bytes.Equal(Verify, []byte(RawData.Verify)) {
		return []byte("fail")
	}
	Cli, ok := ClientMap[string(IDSha256)]
	if !ok {
		return []byte("fail")
	}
	if TimeRv.Add(VerifyTimeout).Before(time.Now()) {
		return []byte("fail")
	}
	if _, err := RequestCacheMap.Get(RawData.Verify); err == nil {
		return []byte("fail")
	} else {
		err := RequestCacheMap.Add(RawData.Verify, nil, VerifyTimeout, nil)
		if err != nil {
			return []byte("fail")
		}
	}
	RealDataByte, err := tool.ECCDecrypt(EncryptData, []byte(Cli.PrivateKey))
	if err != nil {
		return []byte("fail")
	}
	var RealData pool.Receive
	err = gob.NewDecoder(bytes.NewReader(RealDataByte)).Decode(&RealData)
	if err != nil {
		return []byte("fail")
	}
	rt := clientCacheMapAdd(IDSha256, RealData, Cli.TTL)
	if rt {
		return []byte("success")
	} else {
		return []byte("fail")
	}
}

func EasyHandler(cfg ConfigParseTransportEasy, addresses []string) {
	wg := sync.WaitGroup{}
	for _, v := range addresses {
		wg.Add(1)
		go func(v string) {
			defer wg.Done()
			IP, err := netip.ParseAddr(v)
			if err != nil {
				CIDR, err := netip.ParsePrefix(v)
				if err != nil {
					return
				}
				if cfg.AutoCheck.Enable {
					_ = EasyCacheMap.Add(CIDR, true, -1, func(item cachemap.CacheItem) {
						Log.Println(logplus.Warning, fmt.Sprintf("easy: cidr [%s] expired", item.Key.(netip.Prefix).String()))
						GlobalChan <- struct{}{}
					})
					Log.Println(logplus.Info, fmt.Sprintf("easy: cidr [%s] add to cache", CIDR.String()))
					GlobalChan <- struct{}{}
					go EasyCheckFunc(IP, cfg.AutoCheck.Interval, cfg.AutoCheck.RetryInterval)
				} else {
					_ = EasyCacheMap.Add(CIDR, true, time.Duration(cfg.TTL)*time.Second, func(item cachemap.CacheItem) {
						Log.Println(logplus.Warning, fmt.Sprintf("easy: cidr [%s] expired", item.Key.(netip.Prefix).String()))
						GlobalChan <- struct{}{}
					})
					Log.Println(logplus.Info, fmt.Sprintf("easy: cidr [%s] add to cache", CIDR.String()))
					GlobalChan <- struct{}{}
				}
				return
			}
			if cfg.AutoCheck.Enable {
				_ = EasyCacheMap.Add(IP, true, -1, func(item cachemap.CacheItem) {
					Log.Println(logplus.Warning, fmt.Sprintf("easy: ip [%s] expired", item.Key.(netip.Addr).String()))
					GlobalChan <- struct{}{}
				})
				Log.Println(logplus.Info, fmt.Sprintf("easy: ip [%s] add to cache", IP.String()))
				GlobalChan <- struct{}{}
				go EasyCheckFunc(IP, cfg.AutoCheck.Interval, cfg.AutoCheck.RetryInterval)
			} else {
				_ = EasyCacheMap.Add(IP, true, time.Duration(cfg.TTL)*time.Second, func(item cachemap.CacheItem) {
					Log.Println(logplus.Warning, fmt.Sprintf("easy: ip [%s] expired", item.Key.(netip.Addr).String()))
					GlobalChan <- struct{}{}
				})
				Log.Println(logplus.Info, fmt.Sprintf("easy: ip [%s] add to cache", IP.String()))
				GlobalChan <- struct{}{}
			}
		}(v)
	}
	wg.Wait()
}

func clientCacheMapAdd(IDSha256 []byte, d pool.Receive, TTLSet int64) bool {
	ClientLock.Lock()
	defer ClientLock.Unlock()
	m := ClientCacheMap[string(IDSha256)]
	var TTL time.Duration
	if d.TTL > 0 {
		TTL = d.TTL
	}
	if TTLSet > 0 {
		if d.TTL > time.Duration(TTLSet)*time.Second {
			TTL = time.Duration(TTLSet) * time.Second
		}
	}
	if TTL == 0 {
		TTL = -1
	}
	Call := false
	if d.Data.IPv4 != nil && len(d.Data.IPv4) > 0 {
		for _, v := range d.Data.IPv4 {
			if _, err := m.Get(v); err != nil {
				err := m.Add(v, true, TTL, func(item cachemap.CacheItem) {
					Log.Println(logplus.Warning, fmt.Sprintf("ip [%s] expired", item.Key.(netip.Addr).String()))
					GlobalChan <- struct{}{}
				})
				if err != nil {
					return false
				}
				Call = true
			} else {
				err := m.SetTTL(v, TTL, true)
				if err != nil {
					return false
				}
			}
		}
	}
	if d.Data.IPv6 != nil && len(d.Data.IPv6) > 0 {
		for _, v := range d.Data.IPv6 {
			if _, err := m.Get(v); err != nil {
				err := m.Add(v, true, TTL, func(item cachemap.CacheItem) {
					Log.Println(logplus.Warning, fmt.Sprintf("ip [%s] expired", item.Key.(netip.Addr).String()))
					GlobalChan <- struct{}{}
				})
				if err != nil {
					return false
				}
				Call = true
			} else {
				err := m.SetTTL(v, TTL, true)
				if err != nil {
					return false
				}
			}
		}
	}
	if d.Data.CIDRv4 != nil && len(d.Data.CIDRv4) > 0 {
		for _, v := range d.Data.CIDRv4 {
			if _, err := m.Get(v); err != nil {
				err := m.Add(v, true, TTL, func(item cachemap.CacheItem) {
					Log.Println(logplus.Warning, fmt.Sprintf("cidr [%s] expired", item.Key.(netip.Prefix).String()))
					GlobalChan <- struct{}{}
				})
				if err != nil {
					return false
				}
				Call = true
			} else {
				err := m.SetTTL(v, TTL, true)
				if err != nil {
					return false
				}
			}
		}
	}
	if d.Data.CIDRv6 != nil && len(d.Data.CIDRv6) > 0 {
		for _, v := range d.Data.CIDRv6 {
			if _, err := m.Get(v); err != nil {
				err := m.Add(v, true, TTL, func(item cachemap.CacheItem) {
					Log.Println(logplus.Warning, fmt.Sprintf("cidr [%s] expired", item.Key.(netip.Prefix).String()))
					GlobalChan <- struct{}{}
				})
				if err != nil {
					return false
				}
				Call = true
			} else {
				err := m.SetTTL(v, TTL, true)
				if err != nil {
					return false
				}
			}
		}
	}
	if Call {
		GlobalChan <- struct{}{}
	}
	return true
}

func globalRun(ctx context.Context) {
	for {
		select {
		case <-GlobalChan:
			switch len(GlobalChan) {
			case 0:
			default:
				continue
			}
			Temp := pool.NetAddrSlice{
				IPv4:   make([]netip.Addr, 0),
				IPv6:   make([]netip.Addr, 0),
				CIDRv4: make([]netip.Prefix, 0),
				CIDRv6: make([]netip.Prefix, 0),
			}
			Stop := false
			RvChan := make(chan interface{}, 2048)
			WG := sync.WaitGroup{}
			WG.Add(1)
			go func() {
				defer WG.Done()
				for {
					switch {
					case len(RvChan) > 0:
						d, ok := <-RvChan
						if !ok {
							continue
						}
						switch d.(type) {
						case netip.Addr:
							addr := d.(netip.Addr)
							if addr.Is4() {
								Temp.IPv4 = append(Temp.IPv4, addr)
							} else if addr.Is6() {
								Temp.IPv6 = append(Temp.IPv6, addr)
							}
						case netip.Prefix:
							prefix := d.(netip.Prefix)
							if prefix.Addr().Is4() {
								Temp.CIDRv4 = append(Temp.CIDRv4, prefix)
							} else if prefix.Addr().Is6() {
								Temp.CIDRv6 = append(Temp.CIDRv6, prefix)
							}
						}
					case Stop:
						return
					default:
						<-time.After(800 * time.Millisecond)
					}
				}
			}()
			ClientLock.Lock()
			for _, cm := range ClientCacheMap {
				cm.Foreach(func(item cachemap.CacheItem) {
					RvChan <- item.Key
				})
			}
			EasyCacheMap.Foreach(func(item cachemap.CacheItem) {
				RvChan <- item.Key
			})
			ClientLock.Unlock()
			Stop = true
			WG.Wait()
			diff, change := pool.DiffNetAddrSlice(GlobalCacheMap, Temp)
			GlobalCacheMap = Temp
			if change {
				Do(diff)
			}
		case <-ctx.Done():
			return
		}
	}
}

func Do(d pool.Send) {
	CmdRun := func(s ConfigParseScriptBasic, v string) {
		ShellReal := Shell
		if s.Shell != "" {
			ShellReal = s.Shell
		}
		ShellArgReal := ShellArg
		if s.ShellArg != "" {
			ShellArgReal = s.ShellArg
		}
		ShellReal = strings.ReplaceAll(ShellReal, "%#{s}#%", v)
		ShellArgReal = strings.ReplaceAll(ShellArgReal, "%#{s}#%", v)
		c := strings.ReplaceAll(s.Script, "%#{s}#%", v)
		stdout, stderr, err := command.Run(ShellReal, ShellArgReal, c)
		ScriptShow := func() string {
			if c != "" {
				return c
			} else {
				return ShellReal + " " + ShellArgReal
			}
		}()
		if err != nil {
			if s.Fatal {
				Log.Fatalln(logplus.Fatal, fmt.Sprintf("run script [%s] error: %s , stdout: %s, stderr: %s", ScriptShow, err, stdout, stderr))
			}
			if s.Return {
				Log.Println(logplus.Error, fmt.Sprintf("run script [%s] error: %s , stdout: %s, stderr: %s", ScriptShow, err, stdout, stderr))
			}
		} else {
			if s.Return {
				Log.Println(logplus.Info, fmt.Sprintf("run script [%s] success, stdout: %s", ScriptShow, stdout))
			}
		}
	}
	WG := sync.WaitGroup{}
	WG.Add(1)
	go func() {
		defer WG.Done()
		if d.Add.IPv4 != nil && len(d.Add.IPv4) > 0 {
			for _, v := range d.Add.IPv4 {
				if CommandSlice.IPv4Add != nil && len(CommandSlice.IPv4Add) > 0 {
					for _, s := range CommandSlice.IPv4Add {
						CmdRun(s, v.String())
					}
				}
				if IPSet.Enable && IPSetSupport && IPSet.Name4 != "" {
					err := ipset.CheckAndAddAddr(IPSet.Name4, v)
					if err != nil {
						Log.Println(logplus.Error, fmt.Sprintf("ipset add ip [%s] fail, error: %s", v.String(), err))
					} else {
						Log.Println(logplus.Info, fmt.Sprintf("ipset add ip: %s", v.String()))
					}
				}
				Log.Println(logplus.Info, fmt.Sprintf("add ip: %s", v.String()))
			}
		}
		if d.Del.IPv4 != nil && len(d.Del.IPv4) > 0 {
			for _, v := range d.Del.IPv4 {
				if CommandSlice.IPv4Del != nil && len(CommandSlice.IPv4Del) > 0 {
					for _, s := range CommandSlice.IPv4Del {
						CmdRun(s, v.String())
					}
				}
				if IPSet.Enable && IPSetSupport && IPSet.Name4 != "" {
					err := ipset.CheckAndDelAddr(IPSet.Name4, v)
					if err != nil {
						Log.Println(logplus.Error, fmt.Sprintf("ipset del ip [%s] fail, error: %s", v.String(), err))
					} else {
						Log.Println(logplus.Info, fmt.Sprintf("ipset del ip: %s", v.String()))
					}
				}
				Log.Println(logplus.Info, fmt.Sprintf("del ip: %s", v.String()))
			}
		}
		if d.Add.CIDRv4 != nil && len(d.Add.CIDRv4) > 0 {
			for _, v := range d.Add.CIDRv4 {
				if CommandSlice.CIDRv4Add != nil && len(CommandSlice.CIDRv4Add) > 0 {
					for _, s := range CommandSlice.CIDRv4Add {
						CmdRun(s, v.String())
					}
				}
				if IPSet.Enable && IPSetSupport && IPSet.Name4 != "" {
					err := ipset.CheckAndAddPrefix(IPSet.Name4, v)
					if err != nil {
						Log.Println(logplus.Error, fmt.Sprintf("ipset add cidr [%s] fail, error: %s", v.String(), err))
					} else {
						Log.Println(logplus.Info, fmt.Sprintf("ipset add cidr: %s", v.String()))
					}
				}
				Log.Println(logplus.Info, fmt.Sprintf("add cidr: %s", v.String()))
			}
		}
		if d.Del.CIDRv4 != nil && len(d.Del.CIDRv4) > 0 {
			for _, v := range d.Del.CIDRv4 {
				if CommandSlice.CIDRv4Del != nil && len(CommandSlice.CIDRv4Del) > 0 {
					for _, s := range CommandSlice.CIDRv4Del {
						CmdRun(s, v.String())
					}
				}
				if IPSet.Enable && IPSetSupport && IPSet.Name4 != "" {
					err := ipset.CheckAndDelPrefix(IPSet.Name4, v)
					if err != nil {
						Log.Println(logplus.Error, fmt.Sprintf("ipset del cidr [%s] fail, error: %s", v.String(), err))
					} else {
						Log.Println(logplus.Info, fmt.Sprintf("ipset del cidr: %s", v.String()))
					}
				}
				Log.Println(logplus.Info, fmt.Sprintf("del cidr: %s", v.String()))
			}
		}
	}()
	WG.Add(1)
	go func() {
		defer WG.Done()
		if d.Add.IPv6 != nil && len(d.Add.IPv6) > 0 {
			for _, v := range d.Add.IPv6 {
				if CommandSlice.IPv6Add != nil && len(CommandSlice.IPv6Add) > 0 {
					for _, s := range CommandSlice.IPv6Add {
						CmdRun(s, v.String())
					}
				}
				if IPSet.Enable && IPSetSupport && IPSet.Name6 != "" {
					err := ipset.CheckAndAddAddr(IPSet.Name6, v)
					if err != nil {
						Log.Println(logplus.Error, fmt.Sprintf("ipset add ip [%s] fail, error: %s", v.String(), err))
					} else {
						Log.Println(logplus.Info, fmt.Sprintf("ipset add ip: %s", v.String()))
					}
				}
				Log.Println(logplus.Info, fmt.Sprintf("add ip: %s", v.String()))
			}
		}
		if d.Del.IPv6 != nil && len(d.Del.IPv6) > 0 {
			for _, v := range d.Del.IPv6 {
				if CommandSlice.IPv6Del != nil && len(CommandSlice.IPv6Del) > 0 {
					for _, s := range CommandSlice.IPv6Del {
						CmdRun(s, v.String())
					}
				}
				if IPSet.Enable && IPSetSupport && IPSet.Name6 != "" {
					err := ipset.CheckAndDelAddr(IPSet.Name6, v)
					if err != nil {
						Log.Println(logplus.Error, fmt.Sprintf("ipset del ip [%s] fail, error: %s", v.String(), err))
					} else {
						Log.Println(logplus.Info, fmt.Sprintf("ipset del ip: %s", v.String()))
					}
				}
				Log.Println(logplus.Info, fmt.Sprintf("del ip: %s", v.String()))
			}
		}
		if d.Add.CIDRv6 != nil && len(d.Add.CIDRv6) > 0 {
			for _, v := range d.Add.CIDRv6 {
				if CommandSlice.CIDRv6Add != nil && len(CommandSlice.CIDRv6Add) > 0 {
					for _, s := range CommandSlice.CIDRv6Add {
						CmdRun(s, v.String())
					}
				}
				if IPSet.Enable && IPSetSupport && IPSet.Name6 != "" {
					err := ipset.CheckAndAddPrefix(IPSet.Name6, v)
					if err != nil {
						Log.Println(logplus.Error, fmt.Sprintf("ipset add cidr [%s] fail, error: %s", v.String(), err))
					} else {
						Log.Println(logplus.Info, fmt.Sprintf("ipset add cidr: %s", v.String()))
					}
				}
				Log.Println(logplus.Info, fmt.Sprintf("add cidr: %s", v.String()))
			}
		}
		if d.Del.CIDRv6 != nil && len(d.Del.CIDRv6) > 0 {
			for _, v := range d.Del.CIDRv6 {
				if CommandSlice.CIDRv6Del != nil && len(CommandSlice.CIDRv6Del) > 0 {
					for _, s := range CommandSlice.CIDRv6Del {
						CmdRun(s, v.String())
					}
				}
				if IPSet.Enable && IPSetSupport && IPSet.Name6 != "" {
					err := ipset.CheckAndDelPrefix(IPSet.Name6, v)
					if err != nil {
						Log.Println(logplus.Error, fmt.Sprintf("ipset del cidr [%s] fail, error: %s", v.String(), err))
					} else {
						Log.Println(logplus.Info, fmt.Sprintf("ipset del cidr: %s", v.String()))
					}
				}
				Log.Println(logplus.Info, fmt.Sprintf("del cidr: %s", v.String()))
			}
		}
	}()
	WG.Wait()
}
