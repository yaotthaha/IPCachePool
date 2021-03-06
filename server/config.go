package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
)

type ConfigParse struct {
	Log       ConfigParseLog       `json:"log"`
	Clients   []ConfigParseClient  `json:"clients"`
	Transport ConfigParseTransport `json:"transport"`
	Scripts   ConfigParseScript    `json:"scripts"`
	IPSet     ConfigParseIPSet     `json:"ipset"`
	Shell     string               `json:"shell"`
	ShellArg  string               `json:"shell_arg"`
}

type ConfigParseLog struct {
	File  string `json:"file"`
	Debug bool   `json:"debug"`
}

type ConfigParseIPSet struct {
	Enable bool   `json:"enable"`
	Name4  string `json:"name4"`
	Name6  string `json:"name6"`
}

type ConfigParseClient struct {
	Name      string `json:"name"`
	ClientID  string `json:"client_id"`
	PublicKey string `json:"public_key"`
	TTL       int64  `json:"ttl"`
}

type ConfigParseScriptBasic struct {
	Shell    string `json:"shell"`
	ShellArg string `json:"shell_arg"`
	Script   string `json:"script"`
	Fatal    bool   `json:"fatal"`
	Return   bool   `json:"return"`
}

type ConfigParseScript struct {
	Pre       []ConfigParseScriptBasic `json:"pre"`
	Post      []ConfigParseScriptBasic `json:"post"`
	IPv4Add   []ConfigParseScriptBasic `json:"ipv4add"`
	IPv4Del   []ConfigParseScriptBasic `json:"ipv4del"`
	IPv6Add   []ConfigParseScriptBasic `json:"ipv6add"`
	IPv6Del   []ConfigParseScriptBasic `json:"ipv6del"`
	CIDRv4Add []ConfigParseScriptBasic `json:"cidrv4add"`
	CIDRv4Del []ConfigParseScriptBasic `json:"cidrv4del"`
	CIDRv6Add []ConfigParseScriptBasic `json:"cidrv6add"`
	CIDRv6Del []ConfigParseScriptBasic `json:"cidrv6del"`
}

type ConfigParseTransport struct {
	Listen string                    `json:"listen"`
	Port   uint16                    `json:"port"`
	HTTP   ConfigParseTransportHTTP  `json:"http"`
	TLS    ConfigParseTransportTLS   `json:"tls"`
	HTTP3  ConfigParseTransportHTTP3 `json:"http3"`
	Easy   ConfigParseTransportEasy  `json:"easy"`
}

type ConfigParseTransportHTTP struct {
	Path         string `json:"path"`
	RealIPHeader string `json:"real_ip_header"`
}

type ConfigParseTransportTLS struct {
	Enable            bool     `json:"enable"`
	Cert              string   `json:"cert"`
	Key               string   `json:"key"`
	CA                []string `json:"ca"`
	IgnoreVerify      bool     `json:"ignore_verify"`
	RequireClientCert uint     `json:"require_client_cert"`
	ALPN              string   `json:"alpn"`
}

type ConfigParseTransportHTTP3 struct {
	Enable bool `json:"enable"`
	Only   bool `json:"only"`
}

type ConfigParseTransportEasy struct {
	Enable    bool                              `json:"enable"`
	Path      string                            `json:"path"`
	Key       string                            `json:"key"`
	AutoCheck ConfigParseTransportEasyAutoCheck `json:"auto_check"`
	TTL       uint64                            `json:"ttl"`
}

type ConfigParseTransportEasyAutoCheck struct {
	Enable        bool `json:"enable"`
	Interval      uint `json:"interval"`
	RetryInterval uint `json:"retry_interval"`
}

//

type ConfigTransport struct {
	Listen string
	Port   uint16
	HTTP   ConfigTransportHTTP
	TLS    ConfigTransportTLS
	HTTP3  ConfigTransportHTTP3
	Easy   ConfigParseTransportEasy
}

type ConfigTransportHTTP struct {
	Path         string
	RealIPHeader string
}

type ConfigTransportTLS struct {
	Enable            bool
	Cert              []byte
	Key               []byte
	CA                [][]byte
	IgnoreVerify      bool
	RequireClientCert uint
	ALPN              string
}

type ConfigTransportHTTP3 struct {
	Enable bool
	Only   bool
}

type Config struct {
	Log       ConfigParseLog
	Clients   []ConfigParseClient
	Scripts   ConfigParseScript
	IPSet     ConfigParseIPSet
	Transport ConfigTransport
	Shell     string
	ShellArg  string
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
	if len(configParse.Clients) > 0 {
		config.Clients = make([]ConfigParseClient, 0)
		T1 := make(map[string]int)
		T2 := make(map[string]int)
		for _, v := range configParse.Clients {
			if _, ok := T1[v.Name]; ok {
				return nil, fmt.Errorf("client name %s is not unique", v.Name)
			} else {
				T1[v.Name]++
			}
			if _, ok := T2[v.ClientID]; ok {
				return nil, fmt.Errorf("client id %s is not unique", v.ClientID)
			} else {
				T2[v.ClientID]++
			}
			if v.PublicKey == "" {
				return nil, fmt.Errorf("client %s has no public key", v.Name)
			}
			config.Clients = append(config.Clients, ConfigParseClient{
				Name:      v.Name,
				ClientID:  v.ClientID,
				PublicKey: v.PublicKey,
				TTL:       v.TTL,
			})
		}
	} else {
		return nil, errors.New(fmt.Sprintf("no clients included"))
	}
	if configParse.Transport.Listen != "" {
		config.Transport.Listen = strings.TrimSpace(configParse.Transport.Listen)
	} else {
		return nil, errors.New("no transport listen address")
	}
	if configParse.Transport.Port != 0 && configParse.Transport.Port != 65535 {
		config.Transport.Port = configParse.Transport.Port
	} else {
		return nil, errors.New("no transport port")
	}
	if configParse.Transport.HTTP.Path != "" {
		if configParse.Transport.HTTP.Path[0] != '/' {
			configParse.Transport.HTTP.Path = "/" + configParse.Transport.HTTP.Path
		} else {
			config.Transport.HTTP.Path = configParse.Transport.HTTP.Path
		}
	} else {
		config.Transport.HTTP.Path = "/"
	}
	if configParse.Transport.HTTP.RealIPHeader != "" {
		config.Transport.HTTP.RealIPHeader = configParse.Transport.HTTP.RealIPHeader
	}
	if configParse.Transport.TLS.Enable {
		config.Transport.TLS.Enable = true
		if configParse.Transport.TLS.Cert != "" && configParse.Transport.TLS.Key != "" {
			config.Transport.TLS.Cert, err = ioutil.ReadFile(configParse.Transport.TLS.Cert)
			if err != nil {
				return nil, errors.New("no transport tls cert: " + err.Error())
			}
			config.Transport.TLS.Key, err = ioutil.ReadFile(configParse.Transport.TLS.Key)
			if err != nil {
				return nil, errors.New("no transport tls key: " + err.Error())
			}
		} else {
			return nil, errors.New("no transport tls cert or(and) key")
		}
		if configParse.Transport.TLS.CA != nil && len(configParse.Transport.TLS.CA) > 0 {
			CAPool := make([][]byte, 0)
			for _, C := range configParse.Transport.TLS.CA {
				if C != "" {
					CA, err := ioutil.ReadFile(C)
					if err != nil {
						return nil, errors.New("no transport tls ca: " + err.Error())
					}
					CAPool = append(config.Transport.TLS.CA, CA)
				}
			}
			if len(CAPool) > 0 {
				config.Transport.TLS.CA = CAPool
			}
		}
		config.Transport.TLS.RequireClientCert = configParse.Transport.TLS.RequireClientCert
		if configParse.Transport.TLS.ALPN != "" {
			config.Transport.TLS.ALPN = configParse.Transport.TLS.ALPN
		} else {
			config.Transport.TLS.ALPN = "IPCachePool"
		}
		config.Transport.TLS.IgnoreVerify = configParse.Transport.TLS.IgnoreVerify
	} else {
		config.Transport.TLS.Enable = false
	}
	if configParse.Transport.HTTP3.Enable && !config.Transport.TLS.Enable {
		return nil, errors.New("HTTP/3 Must Has TLS Support")
	}
	config.Transport.HTTP3.Enable = configParse.Transport.HTTP3.Enable
	config.Transport.HTTP3.Only = configParse.Transport.HTTP3.Only
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
	config.Scripts = configParse.Scripts
	if configParse.IPSet.Enable {
		s := 0
		if configParse.IPSet.Name4 != "" {
			config.IPSet.Name4 = configParse.IPSet.Name4
			s++
		}
		if configParse.IPSet.Name6 != "" {
			config.IPSet.Name6 = configParse.IPSet.Name6
			s++
		}
		if s == 0 {
			return nil, errors.New("no ipset name")
		}
		config.IPSet.Enable = configParse.IPSet.Enable
	} else {
		config.IPSet.Enable = false
	}
	if configParse.Transport.Easy.Enable {
		if configParse.Transport.Easy.Path != "" {
			if configParse.Transport.Easy.Path[0] != '/' {
				configParse.Transport.Easy.Path = "/" + configParse.Transport.Easy.Path
			} else {
				config.Transport.Easy.Path = configParse.Transport.Easy.Path
			}
		} else {
			return nil, errors.New("no transport easy path")
		}
		if configParse.Transport.Easy.Key == "" {
			return nil, errors.New("no transport easy key")
		}
		if configParse.Transport.Easy.TTL == 0 {
			configParse.Transport.Easy.TTL = 360
		}
		if configParse.Transport.Easy.AutoCheck.Enable {
			if configParse.Transport.Easy.AutoCheck.Interval == 0 {
				configParse.Transport.Easy.AutoCheck.Interval = 30
			}
			if configParse.Transport.Easy.AutoCheck.RetryInterval == 0 {
				configParse.Transport.Easy.AutoCheck.RetryInterval = 60
			}
		}
	}
	config.Transport.Easy = configParse.Transport.Easy
	return config, nil
}
