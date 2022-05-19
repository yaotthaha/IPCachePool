package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"github.com/yaotthaha/IPCachePool/command"
	"github.com/yaotthaha/IPCachePool/ipset"
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
	LogFile       *os.File
	Log           *log.Logger
	ReadTimeout   = 20 * time.Second
	WriteTimeout  = 20 * time.Second
	VerifyTimeout = 30 * time.Second
)

var (
	ClientMap       map[string]ConfigParseClient
	ClientCacheMap  map[string]cachemap.CacheMap
	ClientLock      sync.Mutex
	GlobalCacheMap  pool.NetAddrSlice
	GlobalChan      chan struct{}
	RequestCacheMap cachemap.CacheMap
	CommandSlice    ConfigParseScript
	IPSet           ConfigParseIPSet
	Shell           string
	ShellArg        string
	IPSetSupport    bool
)

func (cfg *Config) ServerRun(ctx context.Context) {
	if cfg.LogFile != "" {
		var err error
		LogFile, err = os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
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
	ClientMap = make(map[string]ConfigParseClient)
	ClientCacheMap = make(map[string]cachemap.CacheMap)
	for _, v := range cfg.Clients {
		IDSha256 := string(tool.Sha256([]byte(v.ID)))
		ClientMap[IDSha256] = v
		ClientCacheMap[IDSha256] = cachemap.NewCacheMap()
	}
	if cfg.IPSet.Enable {
		err := ipset.Check()
		if err != nil {
			Log.Println(fmt.Sprintf("ipset not support: %s", err))
			IPSetSupport = false
		} else {
			s := 0
			err = ipset.Create(cfg.IPSet.Name4, "4")
			if err != nil && !strings.Contains(err.Error(), "exist") {
				Log.Println(fmt.Sprintf("ipset create error: %s", err))
				s++
			} else {
				Log.Println(fmt.Sprintf("ipset [%s] create success", cfg.IPSet.Name4))
			}
			err = ipset.Create(cfg.IPSet.Name6, "6")
			if err != nil && !strings.Contains(err.Error(), "exist") {
				Log.Println(fmt.Sprintf("ipset create error: %s", err))
				s++
			} else {
				Log.Println(fmt.Sprintf("ipset [%s] create success", cfg.IPSet.Name6))
			}
			if s != 0 {
				IPSetSupport = false
				Log.Println("ipset not support")
				err := ipset.Destroy(cfg.IPSet.Name4, "4")
				if err == nil {
					Log.Println(fmt.Sprintf("iipset [%s] destroy success", cfg.IPSet.Name4))
				}
				err = ipset.Destroy(cfg.IPSet.Name6, "6")
				if err == nil {
					Log.Println(fmt.Sprintf("ipset [%s] destroy success", cfg.IPSet.Name6))
				}
			} else {
				IPSetSupport = true
			}
		}
	} else {
		IPSetSupport = false
	}
	if cfg.Scripts.Pre != nil && len(cfg.Scripts.Pre) > 0 {
		for _, v := range cfg.Scripts.Pre {
			stdout, stderr, err := command.Run(cfg.Shell, cfg.ShellArg, v.Script)
			if err != nil {
				if v.Fatal {
					Log.Fatalln(fmt.Sprintf("run pre script [%s] error: %s , stdout: %s, stderr: %s", v.Script, err, stdout, stderr))
				}
				if v.Return {
					Log.Println(fmt.Sprintf("run pre script [%s] error: %s , stdout: %s, stderr: %s", v.Script, err, stdout, stderr))
				} else {
					Log.Println(fmt.Sprintf("run pre script %s", v.Script))
				}
			} else {
				if v.Return {
					Log.Println(fmt.Sprintf("run pre script [%s] success, stdout: %s", v.Script, stdout))
				} else {
					Log.Println(fmt.Sprintf("run pre script %s", v.Script))
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
	IPSet = cfg.IPSet
	Shell = cfg.Shell
	ShellArg = cfg.ShellArg
	ListenAddr := net.JoinHostPort(cfg.Transport.Listen, strconv.Itoa(int(cfg.Transport.Port)))
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
				for _, C := range cfg.Transport.TLS.CA {
					if C != nil && len(C) > 0 {
						CertPool.AppendCertsFromPEM(C)
					}
				}
				return CertPool
			}(),
			ClientAuth: func() tls.ClientAuthType {
				switch cfg.Transport.TLS.RequireClientCert {
				case 0:
					return tls.NoClientCert
				case 1:
					return tls.RequireAnyClientCert
				case 2:
					return tls.RequireAndVerifyClientCert
				default:
					log.Fatalln("invalid require client cert:", cfg.Transport.TLS.RequireClientCert)
					return tls.NoClientCert
				}
			}(),
			InsecureSkipVerify: false,
		}
		if cfg.Transport.Type == "quic" {
			if tlsCfg.NextProtos != nil && len(tlsCfg.NextProtos) > 0 {
				tlsCfg.NextProtos = append(tlsCfg.NextProtos, cfg.Transport.TLS.ALPN)
			} else {
				tlsCfg.NextProtos = []string{cfg.Transport.TLS.ALPN}
			}
		}
	}
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		globalRun(ctx)
	}()
	switch cfg.Transport.Type {
	case "tcp":
		wg.Add(1)
		go func() {
			defer wg.Done()
			TCPServerRun(tlsCfg, ctx, ListenAddr)
		}()
	case "http":
		wg.Add(1)
		go func() {
			defer wg.Done()
			HTTPServerRun(tlsCfg, ctx, ListenAddr, cfg.Transport.HTTP)
		}()
	case "quic":
		wg.Add(1)
		go func() {
			defer wg.Done()
			QUICServerRun(tlsCfg, ctx, ListenAddr)
		}()
	}
	wg.Wait()
	Log.Println("server close")
	if cfg.Scripts.Post != nil && len(cfg.Scripts.Post) > 0 {
		for _, v := range cfg.Scripts.Post {
			stdout, stderr, err := command.Run(cfg.Shell, cfg.ShellArg, v.Script)
			if err != nil {
				if v.Fatal {
					Log.Fatalln(fmt.Sprintf("run post script [%s] error: %s , stdout: %s, stderr: %s", v.Script, err, stdout, stderr))
				}
				if v.Return {
					Log.Println(fmt.Sprintf("run post script [%s] error: %s , stdout: %s, stderr: %s", v.Script, err, stdout, stderr))
				} else {
					Log.Println(fmt.Sprintf("run post script %s", v.Script))
				}
			} else {
				if v.Return {
					Log.Println(fmt.Sprintf("run post script [%s] success, stdout: %s", v.Script, stdout))
				} else {
					Log.Println(fmt.Sprintf("run post script %s", v.Script))
				}
			}
		}
	}
	if IPSetSupport {
		err := ipset.Destroy(cfg.IPSet.Name4, "4")
		if err != nil {
			Log.Println(fmt.Sprintf("ipset [%s] destroy fail: %s", cfg.IPSet.Name4, err))
		} else {
			Log.Println(fmt.Sprintf("ipset [%s] destroy success", cfg.IPSet.Name4))
		}
		err = ipset.Destroy(cfg.IPSet.Name6, "6")
		if err != nil {
			Log.Println(fmt.Sprintf("ipset [%s] destroy fail: %s", cfg.IPSet.Name6, err))
		} else {
			Log.Println(fmt.Sprintf("ipset [%s] destroy success", cfg.IPSet.Name6))
		}
	}
	Log.Println("server exit")
}

func TCPServerRun(tlsCfg *tls.Config, ctx context.Context, ListenAddr string) {
	Log.Println("listen on", ListenAddr, "TCP Server")
	var l net.Listener
	var err error
	if tlsCfg != nil {
		l, err = tls.Listen("tcp", ListenAddr, tlsCfg)
	} else {
		l, err = net.Listen("tcp", ListenAddr)
	}
	if err != nil {
		Log.Fatalln("listen error:", err)
	}
	defer func(l net.Listener) {
		err := l.Close()
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			Log.Fatalln("close listener error:", err)
		}
	}(l)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			conn, err := l.Accept()
			if err != nil {
				Log.Println("accept error:", err)
				continue
			}
			go func(conn net.Conn) {
				err := conn.SetReadDeadline(time.Now().Add(ReadTimeout))
				if err != nil {
					Log.Println("set read deadline error:", err)
				}
				err = conn.SetWriteDeadline(time.Now().Add(WriteTimeout))
				if err != nil {
					Log.Println("set write deadline error:", err)
				}
				defer func(conn net.Conn) {
					_ = conn.Close()
				}(conn)
				Log.Println("accept", conn.RemoteAddr())
				buf, err := io.ReadAll(conn)
				if err != nil {
					Log.Println("read error:", err)
				}
				Log.Println("read success")
				rt := serverHandler(buf)
				if rt != nil && len(rt) > 0 {
					_, err := conn.Write(rt)
					if err != nil {
						Log.Println("write error:", err)
					}
				}
			}(conn)
		}
	}
}

func HTTPServerRun(tlsCfg *tls.Config, ctx context.Context, ListenAddr string, HTTPCfg ConfigTransportHTTP) {
	Log.Println("listen on", ListenAddr, "HTTP Server")
	l, err := net.Listen("tcp", ListenAddr)
	if err != nil {
		Log.Fatalln("listen error:", err)
	}
	defer func(l net.Listener) {
		err := l.Close()
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			Log.Fatalln("close listener error:", err)
		}
	}(l)
	s := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			Log.Println("accept", r.RemoteAddr)
			if r.URL.Path != HTTPCfg.Path {
				Log.Println("path not match", r.URL.Path)
				return
			}
			buf, err := ioutil.ReadAll(r.Body)
			if err != nil {
				Log.Println("read error:", err)
				return
			}
			Log.Println("read success")
			rt := serverHandler(buf)
			if rt != nil && len(rt) > 0 {
				_, err := w.Write(rt)
				if err != nil {
					Log.Println("write error:", err)
				}
			}
		}),
	}
	go func() {
		<-ctx.Done()
		err := s.Shutdown(context.Background())
		if err != nil {
			Log.Println("server shutdown error:", err)
		}
	}()
	if tlsCfg != nil {
		s.TLSConfig = tlsCfg
		err = s.ServeTLS(l, "", "")
	} else {
		err = s.Serve(l)
	}
	if err != nil && err != http.ErrServerClosed {
		Log.Fatalln("server close err:", err)
	}
}

func QUICServerRun(tlsCfg *tls.Config, ctx context.Context, ListenAddr string) {
	if tlsCfg == nil {
		Log.Fatalln("QUIC must support tls")
	}
	Log.Println("listen on", ListenAddr, "QUIC Server")
	quicCfg := &quic.Config{}
	l, err := quic.ListenAddr(ListenAddr, tlsCfg, quicCfg)
	if err != nil {
		Log.Fatalln("listen error:", err)
	}
	defer func(l quic.Listener) {
		err := l.Close()
		if err != nil {
			Log.Fatalln("close listener error:", err)
		}
	}(l)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			Conn, err := l.Accept(context.Background())
			if err != nil {
				Log.Println("accept error:", err)
				continue
			}
			go func(Conn quic.Connection) {
				Log.Println("accept", Conn.RemoteAddr())
				stream, err := Conn.OpenStreamSync(context.Background())
				if err != nil {
					Log.Println("open stream error:", err)
					return
				}
				err = stream.SetReadDeadline(time.Now().Add(ReadTimeout))
				if err != nil {
					Log.Println("set read deadline error:", err)
				}
				err = stream.SetWriteDeadline(time.Now().Add(WriteTimeout))
				if err != nil {
					Log.Println("set write deadline error:", err)
				}
				buf, err := io.ReadAll(stream)
				if err != nil {
					Log.Println("read error:", err)
				}
				Log.Println("read success")
				rt := serverHandler(buf)
				if rt != nil && len(rt) > 0 {
					_, err := stream.Write(rt)
					if err != nil {
						Log.Println("write error:", err)
					}
				}
			}(Conn)
		}
	}
}

func serverHandler(buf []byte) []byte {
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
	if _, err := RequestCacheMap.Get(string(RawData.Verify)); err == nil {
		return []byte("fail")
	} else {
		err := RequestCacheMap.Add(string(RawData.Verify), nil, VerifyTimeout, nil)
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
					Log.Println(fmt.Sprintf("ip [%s] expired", item.Key.(netip.Addr).String()))
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
					Log.Println(fmt.Sprintf("ip [%s] expired", item.Key.(netip.Addr).String()))
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
					Log.Println(fmt.Sprintf("cidr [%s] expired", item.Key.(netip.Prefix).String()))
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
					Log.Println(fmt.Sprintf("cidr [%s] expired", item.Key.(netip.Prefix).String()))
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
	WG := sync.WaitGroup{}
	WG.Add(1)
	go func() {
		defer WG.Done()
		if d.Add.IPv4 != nil && len(d.Add.IPv4) > 0 {
			for _, v := range d.Add.IPv4 {
				if CommandSlice.IPv4Add != nil && len(CommandSlice.IPv4Add) > 0 {
					for _, s := range CommandSlice.IPv4Add {
						c := strings.ReplaceAll(s.Script, "%s", v.String())
						stdout, stderr, err := command.Run(Shell, ShellArg, c)
						if err != nil {
							if s.Fatal {
								Log.Fatalln(fmt.Sprintf("run script [%s] error: %s , stdout: %s, stderr: %s", c, err, stdout, stderr))
							}
							if s.Return {
								Log.Println(fmt.Sprintf("run script [%s] error: %s , stdout: %s, stderr: %s", c, err, stdout, stderr))
							}
						} else {
							if s.Return {
								Log.Println(fmt.Sprintf("run script [%s] success, stdout: %s", c, stdout))
							}
						}
					}
				}
				if IPSet.Enable && IPSetSupport {
					err := ipset.CheckAndAddAddr(IPSet.Name4, v)
					if err != nil {
						Log.Println(fmt.Sprintf("add ip error: %s", err))
					}
					Log.Println(fmt.Sprintf("ipset add ip: %s", v.String()))
				}
				Log.Println(fmt.Sprintf("add ip: %s", v.String()))
			}
		}
		if d.Del.IPv4 != nil && len(d.Del.IPv4) > 0 {
			for _, v := range d.Del.IPv4 {
				if CommandSlice.IPv4Del != nil && len(CommandSlice.IPv4Del) > 0 {
					for _, s := range CommandSlice.IPv4Del {
						c := strings.ReplaceAll(s.Script, "%s", v.String())
						stdout, stderr, err := command.Run(Shell, ShellArg, c)
						if err != nil {
							if s.Fatal {
								Log.Fatalln(fmt.Sprintf("run script [%s] error: %s , stdout: %s, stderr: %s", c, err, stdout, stderr))
							}
							if s.Return {
								Log.Println(fmt.Sprintf("run script [%s] error: %s , stdout: %s, stderr: %s", c, err, stdout, stderr))
							}
						} else {
							if s.Return {
								Log.Println(fmt.Sprintf("run script [%s] success, stdout: %s", c, stdout))
							}
						}
					}
				}
				if IPSet.Enable && IPSetSupport {
					err := ipset.CheckAndDelAddr(IPSet.Name4, v)
					if err != nil {
						Log.Println(fmt.Sprintf("add ip error: %s", err))
					}
					Log.Println(fmt.Sprintf("ipset del ip: %s", v.String()))
				}
				Log.Println(fmt.Sprintf("del ip: %s", v.String()))
			}
		}
		if d.Add.CIDRv4 != nil && len(d.Add.CIDRv4) > 0 {
			for _, v := range d.Add.CIDRv4 {
				if CommandSlice.CIDRv4Add != nil && len(CommandSlice.CIDRv4Add) > 0 {
					for _, s := range CommandSlice.CIDRv4Add {
						c := strings.ReplaceAll(s.Script, "%s", v.String())
						stdout, stderr, err := command.Run(Shell, ShellArg, c)
						if err != nil {
							if s.Fatal {
								Log.Fatalln(fmt.Sprintf("run script [%s] error: %s , stdout: %s, stderr: %s", c, err, stdout, stderr))
							}
							if s.Return {
								Log.Println(fmt.Sprintf("run script [%s] error: %s , stdout: %s, stderr: %s", c, err, stdout, stderr))
							}
						} else {
							if s.Return {
								Log.Println(fmt.Sprintf("run script [%s] success, stdout: %s", c, stdout))
							}
						}
					}
				}
				if IPSet.Enable && IPSetSupport {
					err := ipset.CheckAndAddPrefix(IPSet.Name4, v)
					if err != nil {
						Log.Println(fmt.Sprintf("add ip error: %s", err))
					}
					Log.Println(fmt.Sprintf("ipset add cidr: %s", v.String()))
				}
				Log.Println(fmt.Sprintf("add cidr: %s", v.String()))
			}
		}
		if d.Del.CIDRv4 != nil && len(d.Del.CIDRv4) > 0 {
			for _, v := range d.Del.CIDRv4 {
				if CommandSlice.CIDRv4Del != nil && len(CommandSlice.CIDRv4Del) > 0 {
					for _, s := range CommandSlice.CIDRv4Del {
						c := strings.ReplaceAll(s.Script, "%s", v.String())
						stdout, stderr, err := command.Run(Shell, ShellArg, c)
						if err != nil {
							if s.Fatal {
								Log.Fatalln(fmt.Sprintf("run script [%s] error: %s , stdout: %s, stderr: %s", c, err, stdout, stderr))
							}
							if s.Return {
								Log.Println(fmt.Sprintf("run script [%s] error: %s , stdout: %s, stderr: %s", c, err, stdout, stderr))
							}
						} else {
							if s.Return {
								Log.Println(fmt.Sprintf("run script [%s] success, stdout: %s", c, stdout))
							}
						}
					}
				}
				if IPSet.Enable && IPSetSupport {
					err := ipset.CheckAndDelPrefix(IPSet.Name4, v)
					if err != nil {
						Log.Println(fmt.Sprintf("add ip error: %s", err))
					}
					Log.Println(fmt.Sprintf("ipset del cidr: %s", v.String()))
				}
				Log.Println(fmt.Sprintf("del cidr: %s", v.String()))
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
						c := strings.ReplaceAll(s.Script, "%s", v.String())
						stdout, stderr, err := command.Run(Shell, ShellArg, c)
						if err != nil {
							if s.Fatal {
								Log.Fatalln(fmt.Sprintf("run script [%s] error: %s , stdout: %s, stderr: %s", c, err, stdout, stderr))
							}
							if s.Return {
								Log.Println(fmt.Sprintf("run script [%s] error: %s , stdout: %s, stderr: %s", c, err, stdout, stderr))
							}
						} else {
							if s.Return {
								Log.Println(fmt.Sprintf("run script [%s] success, stdout: %s", c, stdout))
							}
						}
					}
				}
				if IPSet.Enable && IPSetSupport {
					err := ipset.CheckAndAddAddr(IPSet.Name6, v)
					if err != nil {
						Log.Println(fmt.Sprintf("add ip error: %s", err))
					}
					Log.Println(fmt.Sprintf("ipset add ip: %s", v.String()))
				}
				Log.Println(fmt.Sprintf("add ip: %s", v.String()))
			}
		}
		if d.Del.IPv6 != nil && len(d.Del.IPv6) > 0 {
			for _, v := range d.Del.IPv6 {
				if CommandSlice.IPv6Del != nil && len(CommandSlice.IPv6Del) > 0 {
					for _, s := range CommandSlice.IPv6Del {
						c := strings.ReplaceAll(s.Script, "%s", v.String())
						stdout, stderr, err := command.Run(Shell, ShellArg, c)
						if err != nil {
							if s.Fatal {
								Log.Fatalln(fmt.Sprintf("run script [%s] error: %s , stdout: %s, stderr: %s", c, err, stdout, stderr))
							}
							if s.Return {
								Log.Println(fmt.Sprintf("run script [%s] error: %s , stdout: %s, stderr: %s", c, err, stdout, stderr))
							}
						} else {
							if s.Return {
								Log.Println(fmt.Sprintf("run script [%s] success, stdout: %s", c, stdout))
							}
						}
					}
				}
				if IPSet.Enable && IPSetSupport {
					err := ipset.CheckAndDelAddr(IPSet.Name6, v)
					if err != nil {
						Log.Println(fmt.Sprintf("add ip error: %s", err))
					}
					Log.Println(fmt.Sprintf("ipset del ip: %s", v.String()))
				}
				Log.Println(fmt.Sprintf("del ip: %s", v.String()))
			}
		}
		if d.Add.CIDRv6 != nil && len(d.Add.CIDRv6) > 0 {
			for _, v := range d.Add.CIDRv6 {
				if CommandSlice.CIDRv6Add != nil && len(CommandSlice.CIDRv6Add) > 0 {
					for _, s := range CommandSlice.CIDRv6Add {
						c := strings.ReplaceAll(s.Script, "%s", v.String())
						stdout, stderr, err := command.Run(Shell, ShellArg, c)
						if err != nil {
							if s.Fatal {
								Log.Fatalln(fmt.Sprintf("run script [%s] error: %s , stdout: %s, stderr: %s", c, err, stdout, stderr))
							}
							if s.Return {
								Log.Println(fmt.Sprintf("run script [%s] error: %s , stdout: %s, stderr: %s", c, err, stdout, stderr))
							}
						} else {
							if s.Return {
								Log.Println(fmt.Sprintf("run script [%s] success, stdout: %s", c, stdout))
							}
						}
					}
				}
				if IPSet.Enable && IPSetSupport {
					err := ipset.CheckAndAddPrefix(IPSet.Name6, v)
					if err != nil {
						Log.Println(fmt.Sprintf("add ip error: %s", err))
					}
					Log.Println(fmt.Sprintf("ipset add cidr: %s", v.String()))
				}
				Log.Println(fmt.Sprintf("add cidr: %s", v.String()))
			}
		}
		if d.Del.CIDRv6 != nil && len(d.Del.CIDRv6) > 0 {
			for _, v := range d.Del.CIDRv6 {
				if CommandSlice.CIDRv6Del != nil && len(CommandSlice.CIDRv6Del) > 0 {
					for _, s := range CommandSlice.CIDRv6Del {
						c := strings.ReplaceAll(s.Script, "%s", v.String())
						stdout, stderr, err := command.Run(Shell, ShellArg, c)
						if err != nil {
							if s.Fatal {
								Log.Fatalln(fmt.Sprintf("run script [%s] error: %s , stdout: %s, stderr: %s", c, err, stdout, stderr))
							}
							if s.Return {
								Log.Println(fmt.Sprintf("run script [%s] error: %s , stdout: %s, stderr: %s", c, err, stdout, stderr))
							}
						} else {
							if s.Return {
								Log.Println(fmt.Sprintf("run script [%s] success, stdout: %s", c, stdout))
							}
						}
					}
				}
				if IPSet.Enable && IPSetSupport {
					err := ipset.CheckAndDelPrefix(IPSet.Name6, v)
					if err != nil {
						Log.Println(fmt.Sprintf("add ip error: %s", err))
					}
					Log.Println(fmt.Sprintf("ipset del cidr: %s", v.String()))
				}
				Log.Println(fmt.Sprintf("del cidr: %s", v.String()))
			}
		}
	}()
	WG.Wait()
}
