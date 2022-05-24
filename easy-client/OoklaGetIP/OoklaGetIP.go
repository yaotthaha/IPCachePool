package OoklaGetIP

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"github.com/gorilla/websocket"
	"io/ioutil"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

type OoklaPeer struct {
	Host      string
	IPAndPort string
}

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

func OoklaGetAllPeer() ([]OoklaPeer, error) {
	PeerGetURLHost := `www.speedtest.net`
	PeerGetURLPath := `/api/js/servers`
	PeerGetURLQuery := make(map[string]string)
	PeerGetURLQuery["engine"] = "js"
	PeerGetURLQuery["https_functional"] = "true"
	PeerGetURLQuery["limit"] = "16"
	PeerGetURLQuery["ip"] = "1.2.4.8"
	u := url.URL{
		Scheme: "https",
		Host:   PeerGetURLHost,
		Path:   PeerGetURLPath,
		RawQuery: func() string {
			QueryStringSlice := make([]string, 0)
			for k, v := range PeerGetURLQuery {
				QueryStringSlice = append(QueryStringSlice, k+"="+v)
			}
			return strings.Join(QueryStringSlice, "&")
		}(),
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	IP, err := HTTPDNSResolveFunc(PeerGetURLHost)
	if err != nil {
		return nil, err
	}
	req.RemoteAddr = net.JoinHostPort(IP.String(), "443")
	var resp *http.Response
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: func() *tls.Config {
				if u.Scheme == "https" {
					return &tls.Config{InsecureSkipVerify: true}
				} else {
					return nil
				}
			}(),
		},
		Timeout: 3 * time.Second,
	}
	var RetryNum = 0
	for {
		resp, err = client.Do(req)
		if err != nil {
			RetryNum++
		} else {
			break
		}
		if RetryNum == 3 {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	ListRaw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	type PeerListRawStruct struct {
		Host        string `json:"host"`
		CountryCode string `json:"cc"`
	}
	var PeerListRaw []PeerListRawStruct
	err = json.Unmarshal(ListRaw, &PeerListRaw)
	if err != nil {
		return nil, err
	}
	PeerList := make([]OoklaPeer, 0)
	PeerListChan := make(chan OoklaPeer, len(PeerListRaw))
	ResolvePeerIP := func(PeerInfo PeerListRawStruct) (OoklaPeer, error) {
		if PeerInfo.CountryCode != "CN" {
			return OoklaPeer{}, errors.New("not in china")
		} else {
			Host, Port, err := net.SplitHostPort(PeerInfo.Host)
			if err != nil {
				return OoklaPeer{}, err
			}
			ResolveIP, err := HTTPDNSResolveFunc(Host)
			if err != nil {
				return OoklaPeer{}, err
			}
			return OoklaPeer{
				Host:      Host,
				IPAndPort: net.JoinHostPort(ResolveIP.String(), Port),
			}, nil
		}
	}
	var wg sync.WaitGroup
	for _, v := range PeerListRaw {
		wg.Add(1)
		go func(Value PeerListRawStruct) {
			defer wg.Done()
			TempInfo, err := ResolvePeerIP(Value)
			if err != nil {
				return
			}
			PeerListChan <- TempInfo
		}(v)
	}
	wg.Wait()
	for {
		BreakTag := false
		select {
		case Data := <-PeerListChan:
			PeerList = append(PeerList, Data)
		default:
			BreakTag = true
		}
		if BreakTag {
			break
		}
	}
	if len(PeerList) <= 0 {
		return nil, errors.New("peer list is nil")
	}
	return PeerList, nil
}

func OoklaGetAllIP() ([]netip.Addr, error) {
	PeerList, err := OoklaGetAllPeer()
	if err != nil {
		return nil, err
	}
	if len(PeerList) <= 0 {
		return nil, errors.New("PeerList is nil")
	}
	var wg sync.WaitGroup
	IPGetChannel := make(chan net.IP, len(PeerList))
	GetIPDO := func(PeerInfo OoklaPeer) {
		defer func() {
			wg.Done()
		}()
		u := url.URL{
			Scheme: "wss",
			Host:   PeerInfo.Host,
			Path:   "/ws",
		}
		WebSocketDialer := websocket.Dialer{
			NetDial: func(network, addr string) (net.Conn, error) {
				Conn, err := net.Dial(network, PeerInfo.IPAndPort)
				if err != nil {
					return nil, err
				}
				return Conn, nil
			},
			Proxy:            http.ProxyFromEnvironment,
			HandshakeTimeout: 3 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         PeerInfo.Host,
			},
		}
		HTTPRequest := func() http.Header {
			RequestHttpHeader := make(map[string][]string)
			RequestHttpHeader["Accept-Encoding"] = []string{"gzip,deflate,br"}
			RequestHttpHeader["Accept-Language"] = []string{"zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6"}
			RequestHttpHeader["Cache-Control"] = []string{"no-cache"}
			RequestHttpHeader["Origin"] = []string{"https://www.speedtest.net"}
			RequestHttpHeader["Host"] = []string{PeerInfo.Host}
			RequestHttpHeader["Pragma"] = []string{"no-cache"}
			RequestHttpHeader["User-Agent"] = []string{`Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36 Edg/98.0.1108.62`}
			RequestHttpHeader["Dnt"] = []string{"1"}
			if len(RequestHttpHeader) == 0 {
				return nil
			} else {
				return RequestHttpHeader
			}
		}()
		Conn, _, err := WebSocketDialer.Dial(u.String(), HTTPRequest)
		if err != nil {
			return
		}
		defer func(Conn *websocket.Conn) {
			_ = Conn.Close()
		}(Conn)
		err = Conn.WriteMessage(websocket.TextMessage, []byte("GETIP"))
		if err != nil {
			return
		}
		_, messageDataByte, err := Conn.ReadMessage()
		if err != nil {
			return
		}
		IPString := strings.ReplaceAll(strings.Split(string(messageDataByte), " ")[1], "\n", "")
		IP := net.ParseIP(IPString)
		if IP != nil {
			IPGetChannel <- IP
		}
	}
	for _, v := range PeerList {
		wg.Add(1)
		go GetIPDO(v)
	}
	wg.Wait()
	IPSlice := make([]net.IP, 0)
	for {
		BreakTag := false
		select {
		case IPGet := <-IPGetChannel:
			IPSlice = append(IPSlice, IPGet)
		default:
			BreakTag = true
		}
		if BreakTag {
			break
		}
	}
	if len(IPSlice) <= 0 {
		return nil, errors.New("IPSlice is nil")
	}
	IPSliceReal := make([]netip.Addr, 0)
	func() {
		TempMap := make(map[string]int)
		for _, v := range IPSlice {
			TempMap[v.String()]++
		}
		for k := range TempMap {
			IP, _ := netip.ParseAddr(k)
			IPSliceReal = append(IPSliceReal, IP)
		}
	}()
	return IPSliceReal, nil
}
