//go:build linux

package ipset

import (
	"errors"
	"github.com/digineo/go-ipset/v2"
	"github.com/ti-mo/netfilter"
	"net"
	"net/netip"
	"strings"
)

var (
	Conn4 *ipset.Conn
	Conn6 *ipset.Conn
)

func Check() error {
	var err error
	Conn4, err = ipset.Dial(netfilter.ProtoIPv4, nil)
	if err != nil {
		return err
	}
	Conn6, err = ipset.Dial(netfilter.ProtoIPv6, nil)
	if err != nil {
		return err
	}
	return nil
}

func Create(setName string, setType string) error {
	typeName := "hash:net"
	var (
		f    netfilter.ProtoFamily
		Conn *ipset.Conn
	)
	switch setType {
	case "4":
		f = netfilter.ProtoIPv4
		Conn = Conn4
	case "6":
		f = netfilter.ProtoIPv6
		Conn = Conn6
	default:
		return errors.New("set type must be 4 or 6")
	}
	err := Conn.Create(setName, typeName, 0, f)
	return err
}

func AddAddr(setName string, ip ...netip.Addr) error {
	if len(ip) > 0 {
		Entry4 := make([]*ipset.Entry, 0)
		Entry6 := make([]*ipset.Entry, 0)
		for _, v := range ip {
			e := ipset.NewEntry(ipset.EntryIP(net.ParseIP(v.String())), ipset.EntryCidr(uint8(v.BitLen())))
			if v.Is4() {
				Entry4 = append(Entry4, e)
			} else if v.Is6() {
				Entry6 = append(Entry6, e)
			} else {
				return errors.New("invalid ip")
			}
		}
		errSlice := make([]error, 0)
		if len(Entry4) > 0 {
			err := Conn4.Add(setName, Entry4...)
			if err != nil {
				errSlice = append(errSlice, err)
			}
		}
		if len(Entry6) > 0 {
			err := Conn6.Add(setName, Entry6...)
			if err != nil {
				errSlice = append(errSlice, err)
			}
		}
		if len(errSlice) > 0 {
			return errors.New(func() string {
				S := make([]string, 0)
				for _, v := range errSlice {
					S = append(S, v.Error())
				}
				return strings.Join(S, " ")
			}())
		} else {
			return nil
		}
	} else {
		return errors.New("ip is nil")
	}
}

func AddPrefix(setName string, cidr ...netip.Prefix) error {
	if len(cidr) > 0 {
		Entry4 := make([]*ipset.Entry, 0)
		Entry6 := make([]*ipset.Entry, 0)
		for _, v := range cidr {
			e := ipset.NewEntry(ipset.EntryIP(net.ParseIP(v.Addr().String())), ipset.EntryCidr(uint8(v.Bits())))
			if v.Addr().Is4() {
				Entry4 = append(Entry4, e)
			} else if v.Addr().Is6() {
				Entry6 = append(Entry6, e)
			} else {
				return errors.New("invalid cidr")
			}
		}
		errSlice := make([]error, 0)
		if len(Entry4) > 0 {
			err := Conn4.Add(setName, Entry4...)
			if err != nil {
				errSlice = append(errSlice, err)
			}
		}
		if len(Entry6) > 0 {
			err := Conn6.Add(setName, Entry6...)
			if err != nil {
				errSlice = append(errSlice, err)
			}
		}
		if len(errSlice) > 0 {
			return errors.New(func() string {
				S := make([]string, 0)
				for _, v := range errSlice {
					S = append(S, v.Error())
				}
				return strings.Join(S, " ")
			}())
		} else {
			return nil
		}
	} else {
		return errors.New("cidr is nil")
	}
}

func DelAddr(setName string, ip ...netip.Addr) error {
	if len(ip) > 0 {
		Entry4 := make([]*ipset.Entry, 0)
		Entry6 := make([]*ipset.Entry, 0)
		for _, v := range ip {
			e := ipset.NewEntry(ipset.EntryIP(net.ParseIP(v.String())), ipset.EntryCidr(uint8(v.BitLen())))
			if v.Is4() {
				Entry4 = append(Entry4, e)
			} else if v.Is6() {
				Entry6 = append(Entry6, e)
			} else {
				return errors.New("invalid ip")
			}
		}
		errSlice := make([]error, 0)
		if len(Entry4) > 0 {
			err := Conn4.Delete(setName, Entry4...)
			if err != nil {
				errSlice = append(errSlice, err)
			}
		}
		if len(Entry6) > 0 {
			err := Conn6.Delete(setName, Entry6...)
			if err != nil {
				errSlice = append(errSlice, err)
			}
		}
		if len(errSlice) > 0 {
			return errors.New(func() string {
				S := make([]string, 0)
				for _, v := range errSlice {
					S = append(S, v.Error())
				}
				return strings.Join(S, " ")
			}())
		} else {
			return nil
		}
	} else {
		return errors.New("ip is nil")
	}
}

func DelPrefix(setName string, cidr ...netip.Prefix) error {
	if len(cidr) > 0 {
		Entry4 := make([]*ipset.Entry, 0)
		Entry6 := make([]*ipset.Entry, 0)
		for _, v := range cidr {
			e := ipset.NewEntry(ipset.EntryIP(net.ParseIP(v.Addr().String())), ipset.EntryCidr(uint8(v.Bits())))
			if v.Addr().Is4() {
				Entry4 = append(Entry4, e)
			} else if v.Addr().Is6() {
				Entry6 = append(Entry6, e)
			} else {
				return errors.New("invalid cidr")
			}
		}
		errSlice := make([]error, 0)
		if len(Entry4) > 0 {
			err := Conn4.Delete(setName, Entry4...)
			if err != nil {
				errSlice = append(errSlice, err)
			}
		}
		if len(Entry6) > 0 {
			err := Conn6.Delete(setName, Entry6...)
			if err != nil {
				errSlice = append(errSlice, err)
			}
		}
		if len(errSlice) > 0 {
			return errors.New(func() string {
				S := make([]string, 0)
				for _, v := range errSlice {
					S = append(S, v.Error())
				}
				return strings.Join(S, " ")
			}())
		} else {
			return nil
		}
	} else {
		return errors.New("cidr is nil")
	}
}

func ExistAddr(setName string, ip netip.Addr) bool {
	var err error
	if ip.Is4() {
		err = Conn4.Test(setName, ipset.EntryIP(net.ParseIP(ip.String())), ipset.EntryCidr(uint8(ip.BitLen())))
	} else if ip.Is6() {
		err = Conn6.Test(setName, ipset.EntryIP(net.ParseIP(ip.String())), ipset.EntryCidr(uint8(ip.BitLen())))
	} else {
		return false
	}
	if err != nil {
		return false
	}
	return true
}

func ExistPrefix(setName string, cidr netip.Prefix) bool {
	var err error
	if cidr.Addr().Is4() {
		err = Conn4.Test(setName, ipset.EntryIP(net.ParseIP(cidr.Addr().String())), ipset.EntryCidr(uint8(cidr.Bits())))
	} else if cidr.Addr().Is6() {
		err = Conn6.Test(setName, ipset.EntryIP(net.ParseIP(cidr.Addr().String())), ipset.EntryCidr(uint8(cidr.Bits())))
	} else {
		return false
	}
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

func Destroy(setName string, setType string) error {
	var Conn *ipset.Conn
	switch setType {
	case "4":
		Conn = Conn4
	case "6":
		Conn = Conn6
	default:
		return errors.New("set type must be 4 or 6")
	}
	err := Conn.Destroy(setName)
	return err
}
