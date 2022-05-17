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
	File string `json:"file"`
}

type ConfigParseScriptBasic struct {
	Script string `json:"script"`
	Fatal  bool   `json:"fatal"`
	Return bool   `json:"return"`
}

type ConfigParseServer struct {
	Name      string                     `json:"name"`
	ID        string                     `json:"id"`
	PublicKey string                     `json:"public_key"`
	Interval  uint                       `json:"interval"`
	TTL       int                        `json:"ttl"`
	Transport ConfigParseServerTransport `json:"transport"`
	Address   string                     `json:"address"`
	Port      uint16                     `json:"port"`
}

type ConfigParseServerTransport struct {
	Type string                         `json:"type"`
	HTTP ConfigParseServerTransportHTTP `json:"http"`
	TLS  ConfigParseServerTransportTLS  `json:"tls"`
}

type ConfigParseServerTransportHTTP struct {
	Host string `json:"host"`
	Path string `json:"path"`
}

type ConfigParseServerTransportTLS struct {
	Enable bool     `json:"enable"`
	Cert   string   `json:"cert"`
	Key    string   `json:"key"`
	CA     []string `json:"ca"`
	SNI    string   `json:"sni"`
	ALPN   string   `json:"alpn"`
	Verify int      `json:"verify"`
}

type Config struct {
	Log      ConfigParseLog
	Shell    string
	ShellArg string
	Script   []ConfigParseScriptBasic
	Servers  []ConfigServer
}

type ConfigServer struct {
	Name      string
	ID        string
	PublicKey string
	Interval  uint
	TTL       int
	Transport ConfigServerTransport
	Address   string
	Port      uint16
}

type ConfigServerTransportHTTP struct {
	Host string
	Path string
}

type ConfigServerTransport struct {
	Type string
	HTTP ConfigServerTransportHTTP
	TLS  ConfigServerTransportTLS
}

type ConfigServerTransportTLS struct {
	Enable bool
	Cert   []byte
	Key    []byte
	CA     [][]byte
	SNI    string
	ALPN   string
	Verify int
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
	config.Log.File = configParse.Log.File
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
			if _, ok := T2[v.ID]; ok {
				return nil, errors.New("duplicate client id")
			} else {
				T2[v.ID]++
				c.ID = v.ID
			}
			if v.PublicKey == "" {
				return nil, errors.New("no public key found")
			} else {
				c.PublicKey = v.PublicKey
			}
			if v.Interval == 0 {
				v.Interval = 30
			}
			c.Interval = v.Interval
			if v.Address == "" {
				return nil, errors.New("no address found")
			} else {
				c.Address = v.Address
			}
			if v.Port != 0 && v.Port != 65535 {
				c.Port = v.Port
			} else {
				return nil, errors.New("invalid port")
			}
			switch v.Transport.Type {
			case "tcp":
				c.Transport.Type = "tcp"
			case "http":
				c.Transport.Type = "http"
				if v.Transport.HTTP.Path != "" {
					if v.Transport.HTTP.Path[0] != '/' {
						c.Transport.HTTP.Path = "/" + v.Transport.HTTP.Path
					} else {
						c.Transport.HTTP.Path = v.Transport.HTTP.Path
					}
				} else {
					c.Transport.HTTP.Path = "/"
				}
			case "quic":
				c.Transport.Type = "quic"
			}
			if v.Transport.TLS.Enable {
				c.Transport.TLS.Enable = true
				if v.Transport.TLS.Cert != "" {
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
					c.Transport.TLS.CA = CAPool
					if v.Transport.TLS.SNI == "" {
						c.Transport.TLS.SNI = v.Address
					} else {
						c.Transport.TLS.SNI = v.Transport.TLS.SNI
					}
					switch v.Transport.Type {
					case "tcp":
					case "http":
					case "quic":
						if v.Transport.TLS.ALPN != "" {
							c.Transport.TLS.ALPN = v.Transport.TLS.ALPN
						} else {
							c.Transport.TLS.ALPN = "IPCachePool-QUIC"
						}
					default:
					}
					switch v.Transport.TLS.Verify {
					case 0, -1, 1:
					default:
						return nil, errors.New("invalid verify")
					}
				} else {
					return nil, errors.New("no cert found")
				}
			} else {
				c.Transport.TLS.Enable = false
			}
			c.TTL = v.TTL
			config.Servers = append(config.Servers, c)
		}
	} else {
		return nil, errors.New("no server found")
	}
	return config, nil
}
