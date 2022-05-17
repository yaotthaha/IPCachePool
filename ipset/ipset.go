package ipset

import (
	"errors"
	"github.com/digineo/go-ipset/v2"
	"github.com/ti-mo/netfilter"
	"net"
	"net/netip"
)

var Conn *ipset.Conn

func Check() error {
	var err error
	Conn, err = ipset.Dial(netfilter.ProtoIPv4, nil)
	return err
}

func Create(setName string, setType string) error {
	typeName := "hash:net"
	var f netfilter.ProtoFamily
	switch setType {
	case "4":
		f = netfilter.ProtoIPv4
	case "6":
		f = netfilter.ProtoIPv6
	default:
		return errors.New("set type must be 4 or 6")
	}
	P, err := Conn.Protocol()
	if err != nil {
		return err
	}
	return Conn.Create(setName, typeName, P.Protocol.Get(), f, ipset.CreateDataHashSize(1024), ipset.CreateDataMaxElem(65535))
}

func AddAddr(setName string, ip netip.Addr) error {
	return Conn.Add(setName, ipset.NewEntry(ipset.EntryIP(net.ParseIP(ip.String())), ipset.EntryCidr(uint8(ip.BitLen()))))
}

func AddPrefix(setName string, cidr netip.Prefix) error {
	return Conn.Add(setName, ipset.NewEntry(ipset.EntryIP(net.ParseIP(cidr.Addr().String())), ipset.EntryCidr(uint8(cidr.Bits()))))
}

func DelAddr(setName string, ip netip.Addr) error {
	return Conn.Delete(setName, ipset.NewEntry(ipset.EntryIP(net.ParseIP(ip.String())), ipset.EntryCidr(uint8(ip.BitLen()))))
}

func DelPrefix(setName string, cidr netip.Prefix) error {
	return Conn.Delete(setName, ipset.NewEntry(ipset.EntryIP(net.ParseIP(cidr.Addr().String())), ipset.EntryCidr(uint8(cidr.Bits()))))
}

func ExistAddr(setName string, ip netip.Addr) bool {
	err := Conn.Test(setName, ipset.EntryIP(net.ParseIP(ip.String())), ipset.EntryCidr(uint8(ip.BitLen())))
	if err != nil {
		return false
	}
	return true
}

func ExistPrefix(setName string, cidr netip.Prefix) bool {
	err := Conn.Test(setName, ipset.EntryIP(net.ParseIP(cidr.Addr().String())), ipset.EntryCidr(uint8(cidr.Bits())))
	if err != nil {
		return false
	}
	return true
}

func CheckAndAddAddr(setName string, ip netip.Addr) error {
	if !ExistAddr(setName, ip) {
		return AddAddr(setName, ip)
	}
	return nil
}

func CheckAndAddPrefix(setName string, cidr netip.Prefix) error {
	if !ExistPrefix(setName, cidr) {
		return AddPrefix(setName, cidr)
	}
	return nil
}

func CheckAndDelAddr(setName string, ip netip.Addr) error {
	if ExistAddr(setName, ip) {
		return DelAddr(setName, ip)
	}
	return nil
}

func CheckAndDelPrefix(setName string, cidr netip.Prefix) error {
	if ExistPrefix(setName, cidr) {
		return DelPrefix(setName, cidr)
	}
	return nil
}
