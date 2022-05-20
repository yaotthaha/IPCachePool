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
	File    string `json:"file"`
	MoreMsg bool   `json:"more_msg"`
}

type ConfigParseIPSet struct {
	Enable bool   `json:"enable"`
	Name4  string `json:"name4"`
	Name6  string `json:"name6"`
}

type ConfigParseClient struct {
	Name       string `json:"name"`
	ClientID   string `json:"client_id"`
	PrivateKey string `json:"private_key"`
	TTL        int64  `json:"ttl"`
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
	Listen string                   `json:"listen"`
	Port   uint16                   `json:"port"`
	HTTP   ConfigParseTransportHTTP `json:"http"`
	TLS    ConfigParseTransportTLS  `json:"tls"`
}

type ConfigParseTransportHTTP struct {
	Path string `json:"path"`
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

//
//

type ConfigTransport struct {
	Listen string
	Port   uint16
	HTTP   ConfigTransportHTTP
	TLS    ConfigTransportTLS
}

type ConfigTransportHTTP struct {
	Path string
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
			if v.PrivateKey == "" {
				return nil, fmt.Errorf("client %s has no private key", v.Name)
			}
			config.Clients = append(config.Clients, ConfigParseClient{
				Name:       v.Name,
				ClientID:   v.ClientID,
				PrivateKey: v.PrivateKey,
				TTL:        v.TTL,
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
	return config, nil
}
