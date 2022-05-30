package transport

import (
	"net/netip"
)

type Transport struct {
	ID     string `json:"id"`
	Time   string `json:"time"`
	Verify string `json:"verify"`
	Data   struct {
		IPv4   []netip.Addr   `json:"ipv4"`
		IPv6   []netip.Addr   `json:"ipv6"`
		CIDRv4 []netip.Prefix `json:"cidrv4"`
		CIDRv6 []netip.Prefix `json:"cidrv6"`
	} `json:"data"`
	TTL int64 `json:"ttl"`
}
