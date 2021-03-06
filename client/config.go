package client

import (
	"encoding/json"
	"errors"
	"io/ioutil"
)

type ConfigParse struct {
	Log      ConfigParseLog           `json:"log"`
	Shell    string                   `json:"shell"`
	ShellArg string                   `json:"shell_arg"`
	Script   []ConfigParseScriptBasic `json:"script"`
	Servers  []ConfigParseServer      `json:"servers"`
}

type ConfigParseLog struct {
	File  string `json:"file"`
	Debug bool   `json:"debug"`
}

type ConfigParseScriptBasic struct {
	Shell    string `json:"shell"`
	ShellArg string `json:"shell_arg"`
	Script   string `json:"script"`
	Fatal    bool   `json:"fatal"`
	Return   bool   `json:"return"`
}

type ConfigParseServer struct {
	Name           string                     `json:"name"`
	ClientID       string                     `json:"client_id"`
	PrivateKey     string                     `json:"private_key"`
	Interval       uint                       `json:"interval"`
	TTL            int                        `json:"ttl"`
	Transport      ConfigParseServerTransport `json:"transport"`
	RequestTimeout uint                       `json:"request_timeout"`
}

type ConfigParseServerTransport struct {
	Address string                          `json:"address"`
	Port    uint16                          `json:"port"`
	HTTP    ConfigParseServerTransportHTTP  `json:"http"`
	TLS     ConfigParseServerTransportTLS   `json:"tls"`
	HTTP2   ConfigParseServerTransportHTTP2 `json:"http2"`
	HTTP3   ConfigParseServerTransportHTTP3 `json:"http3"`
}

type ConfigParseServerTransportHTTP struct {
	Host string `json:"host"`
	Path string `json:"path"`
}

type ConfigParseServerTransportHTTP2 struct {
	Enable bool `json:"enable"`
}

type ConfigParseServerTransportHTTP3 struct {
	Enable bool `json:"enable"`
}

type ConfigParseServerTransportTLS struct {
	Enable       bool     `json:"enable"`
	Cert         string   `json:"cert"`
	Key          string   `json:"key"`
	CA           []string `json:"ca"`
	SNI          string   `json:"sni"`
	ALPN         string   `json:"alpn"`
	IgnoreVerify bool     `json:"ignore_verify"`
}

type Config struct {
	Log      ConfigParseLog
	Shell    string
	ShellArg string
	Script   []ConfigParseScriptBasic
	Servers  []ConfigServer
}

type ConfigServer struct {
	Name           string
	ClientID       string
	PrivateKey     string
	Interval       uint
	TTL            int
	Transport      ConfigServerTransport
	RequestTimeout uint
}

type ConfigServerTransportHTTP struct {
	Host string
	Path string
}

type ConfigServerTransportHTTP2 struct {
	Enable bool
}

type ConfigServerTransportHTTP3 struct {
	Enable bool
}

type ConfigServerTransport struct {
	Address string
	Port    uint16
	HTTP    ConfigServerTransportHTTP
	TLS     ConfigServerTransportTLS
	HTTP2   ConfigServerTransportHTTP2
	HTTP3   ConfigServerTransportHTTP3
}

type ConfigServerTransportTLS struct {
	Enable       bool
	Cert         []byte
	Key          []byte
	CA           [][]byte
	SNI          string
	ALPN         string
	IgnoreVerify bool
}

func Parse(filename string) (*Config, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	configParse := &ConfigParse{}
	config := &Config{}
	err = json.Unmarshal(data, &configParse)
	if err != nil {
		return nil, err
	}
	config.Log = configParse.Log
	if configParse.Shell != "" {
		config.Shell = configParse.Shell
	} else {
		config.Shell = "bash"
	}
	if configParse.ShellArg != "" {
		config.ShellArg = configParse.ShellArg
	} else {
		config.ShellArg = "-c"
	}
	if len(configParse.Script) > 0 {
		config.Script = configParse.Script
	} else {
		return nil, errors.New("no script found")
	}
	if len(configParse.Servers) > 0 {
		config.Servers = make([]ConfigServer, 0)
		T1 := make(map[string]int)
		T2 := make(map[string]int)
		for _, v := range configParse.Servers {
			var c ConfigServer
			if _, ok := T1[v.Name]; ok {
				return nil, errors.New("duplicate server name")
			} else {
				T1[v.Name]++
				c.Name = v.Name
			}
			if _, ok := T2[v.ClientID]; ok {
				return nil, errors.New("duplicate client id")
			} else {
				T2[v.ClientID]++
				c.ClientID = v.ClientID
			}
			if v.PrivateKey == "" {
				return nil, errors.New("no private key found")
			} else {
				c.PrivateKey = v.PrivateKey
			}
			if v.Interval == 0 {
				v.Interval = 30
			}
			c.Interval = v.Interval
			if v.Transport.Address == "" {
				return nil, errors.New("no address found")
			} else {
				c.Transport.Address = v.Transport.Address
			}
			if v.Transport.Port != 0 && v.Transport.Port != 65535 {
				c.Transport.Port = v.Transport.Port
			} else {
				return nil, errors.New("invalid port")
			}
			if v.Transport.HTTP.Path != "" {
				if v.Transport.HTTP.Path[0] != '/' {
					c.Transport.HTTP.Path = "/" + v.Transport.HTTP.Path
				} else {
					c.Transport.HTTP.Path = v.Transport.HTTP.Path
				}
			} else {
				c.Transport.HTTP.Path = "/"
			}
			if v.Transport.HTTP.Host != "" {
				c.Transport.HTTP.Host = v.Transport.HTTP.Host
			} else {
				c.Transport.HTTP.Host = v.Transport.Address
			}
			if v.Transport.TLS.Enable {
				c.Transport.TLS.Enable = true
				if v.Transport.TLS.Cert != "" && v.Transport.TLS.Key != "" {
					Cert, err := ioutil.ReadFile(v.Transport.TLS.Cert)
					if err != nil {
						return nil, err
					}
					c.Transport.TLS.Cert = Cert
					Key, err := ioutil.ReadFile(v.Transport.TLS.Key)
					if err != nil {
						return nil, err
					}
					c.Transport.TLS.Key = Key
				}
				CAPool := make([][]byte, 0)
				for _, C := range v.Transport.TLS.CA {
					if C != "" {
						CA, err := ioutil.ReadFile(C)
						if err != nil {
							return nil, err
						}
						CAPool = append(CAPool, CA)
					}
				}
				if CAPool != nil && len(CAPool) > 0 {
					c.Transport.TLS.CA = CAPool
				}
				if v.Transport.TLS.SNI == "" {
					c.Transport.TLS.SNI = v.Transport.Address
				} else {
					c.Transport.TLS.SNI = v.Transport.TLS.SNI
				}
				if v.Transport.TLS.ALPN != "" {
					c.Transport.TLS.ALPN = v.Transport.TLS.ALPN
				} else {
					c.Transport.TLS.ALPN = "IPCachePool"
				}
				c.Transport.TLS.IgnoreVerify = v.Transport.TLS.IgnoreVerify
			} else {
				c.Transport.TLS.Enable = false
			}
			if v.Transport.HTTP2.Enable {
				if !c.Transport.TLS.Enable {
					return nil, errors.New("http2 must be used with tls")
				}
				c.Transport.HTTP2.Enable = true
			} else {
				c.Transport.HTTP2.Enable = false
			}
			if v.Transport.HTTP3.Enable {
				if !c.Transport.TLS.Enable {
					return nil, errors.New("http3 must be used with tls")
				}
				c.Transport.HTTP3.Enable = true
			} else {
				c.Transport.HTTP3.Enable = false
			}
			c.TTL = v.TTL
			c.RequestTimeout = v.RequestTimeout
			config.Servers = append(config.Servers, c)
		}
	} else {
		return nil, errors.New("no server found")
	}
	return config, nil
}
