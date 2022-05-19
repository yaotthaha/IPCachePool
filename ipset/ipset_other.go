//go:build !linux

package ipset

import (
	"errors"
	"net/netip"
)

func Check() error {
	return errors.New("not support")
}

func Create(setName string, setType string) error {
	return errors.New("not support")
}

func AddAddr(setName string, ip netip.Addr) error {
	return errors.New("not support")
}

func AddPrefix(setName string, cidr netip.Prefix) error {
	return errors.New("not support")
}

func DelAddr(setName string, ip netip.Addr) error {
	return errors.New("not support")
}

func DelPrefix(setName string, cidr netip.Prefix) error {
	return errors.New("not support")
}

func ExistAddr(setName string, ip netip.Addr) bool {
	return false
}

func ExistPrefix(setName string, cidr netip.Prefix) bool {
	return false
}

func CheckAndAddAddr(setName string, ip netip.Addr) error {
	return errors.New("not support")
}

func CheckAndAddPrefix(setName string, cidr netip.Prefix) error {
	return errors.New("not support")
}

func CheckAndDelAddr(setName string, ip netip.Addr) error {
	return errors.New("not support")
}

func CheckAndDelPrefix(setName string, cidr netip.Prefix) error {
	return errors.New("not support")
}

func Destroy(setName string, setType string) error {
	return errors.New("not support")
}
