package easy_client

import (
	"encoding/json"
	"errors"
	"io/ioutil"
)

type RawConfig struct {
	Script []string        `json:"script"`
	Server RawConfigServer `json:"server"`
}

type RawConfigServer struct {
	Address string               `json:"address"`
	Port    uint16               `json:"port"`
	HTTP    RawConfigServerHTTP  `json:"http"`
	TLS     RawConfigServerTLS   `json:"tls"`
	HTTP2   RawConfigServerHTTP2 `json:"http2"`
	HTTP3   RawConfigServerHTTP3 `json:"http3"`
}

type RawConfigServerHTTP struct {
	Host   string            `json:"host"`
	Path   string            `json:"path"`
	Header map[string]string `json:"header"`
}

type RawConfigServerTLS struct {
	Enable       bool     `json:"enable"`
	Cert         string   `json:"cert"`
	Key          string   `json:"key"`
	CA           []string `json:"ca"`
	SNI          string   `json:"sni"`
	ALPN         string   `json:"alpn"`
	IgnoreVerify bool     `json:"ignore_verify"`
}

type RawConfigServerHTTP2 struct {
	Enable bool `json:"enable"`
}

type RawConfigServerHTTP3 struct {
	Enable bool `json:"enable"`
}

//

type Config struct {
	Script []string
	Server ConfigServer
}

type ConfigServer struct {
	Address string
	Port    uint16
	HTTP    RawConfigServerHTTP
	TLS     ConfigServerTLS
	HTTP2   ConfigServerHTTP2
	HTTP3   ConfigServerHTTP3
}

type ConfigServerTLS struct {
	Enable       bool
	Cert         []byte
	Key          []byte
	CA           [][]byte
	SNI          string
	ALPN         string
	IgnoreVerify bool
}

type ConfigServerHTTP2 struct {
	Enable bool
}

type ConfigServerHTTP3 struct {
	Enable bool
}

func Parse(filename string) (*Config, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var raw RawConfig
	err = json.Unmarshal(data, &raw)
	if err != nil {
		return nil, err
	}
	config := &Config{}
	if len(raw.Script) > 0 {
		config.Script = raw.Script
	} else {
		config.Script = nil
	}
	if raw.Server.Address != "" {
		config.Server.Address = raw.Server.Address
	} else {
		return nil, errors.New("server address is empty")
	}
	if raw.Server.Port != 0 && raw.Server.Port != 65535 {
		config.Server.Port = raw.Server.Port
	} else {
		return nil, errors.New("server port is invalid")
	}
	if raw.Server.HTTP.Host != "" {
		config.Server.HTTP.Host = raw.Server.HTTP.Host
	} else {
		return nil, errors.New("server http host is empty")
	}
	if raw.Server.HTTP.Path != "" {
		config.Server.HTTP.Path = raw.Server.HTTP.Path
	} else {
		config.Server.HTTP.Path = "/"
	}
	if len(raw.Server.HTTP.Header) > 0 {
		config.Server.HTTP.Header = raw.Server.HTTP.Header
	} else {
		config.Server.HTTP.Header = nil
	}
	if raw.Server.TLS.Enable {
		config.Server.TLS.Enable = true
		if raw.Server.TLS.Cert != "" {
			Cert, err := ioutil.ReadFile(raw.Server.TLS.Cert)
			if err != nil {
				return nil, err
			}
			config.Server.TLS.Cert = Cert
		}
		if raw.Server.TLS.Key != "" {
			Key, err := ioutil.ReadFile(raw.Server.TLS.Key)
			if err != nil {
				return nil, err
			}
			config.Server.TLS.Key = Key
		}
		if len(raw.Server.TLS.CA) > 0 {
			config.Server.TLS.CA = make([][]byte, 0)
			for _, v := range raw.Server.TLS.CA {
				CA, err := ioutil.ReadFile(v)
				if err != nil {
					return nil, err
				}
				config.Server.TLS.CA = append(config.Server.TLS.CA, CA)
			}
			if len(config.Server.TLS.CA) == 0 {
				config.Server.TLS.CA = nil
			}
		} else {
			config.Server.TLS.CA = nil
		}
		if raw.Server.TLS.SNI != "" {
			config.Server.TLS.SNI = raw.Server.TLS.SNI
		} else {
			config.Server.TLS.SNI = raw.Server.Address
		}
		if raw.Server.TLS.ALPN != "" {
			config.Server.TLS.ALPN = raw.Server.TLS.ALPN
		} else {
			config.Server.TLS.ALPN = "IPCachePool"
		}
		config.Server.TLS.IgnoreVerify = raw.Server.TLS.IgnoreVerify
	} else {
		config.Server.TLS.Enable = false
	}
	config.Server.HTTP2 = ConfigServerHTTP2(raw.Server.HTTP2)
	config.Server.HTTP3 = ConfigServerHTTP3(raw.Server.HTTP3)
	return config, nil
}
