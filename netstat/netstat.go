package netstat

import (
	"bytes"
	"encoding/binary"
	"io/ioutil"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

var (
	PathTCP4 = "/proc/net/tcp"
	PathTCP6 = "/proc/net/tcp6"
	PathUDP4 = "/proc/net/udp"
	PathUDP6 = "/proc/net/udp6"
)

type Protocol string

const (
	TCP Protocol = "TCP"
	UDP Protocol = "UDP"
)

type Item struct {
	Protocol   Protocol
	LocalIP    netip.Addr
	LocalPort  uint16
	RemoteIP   netip.Addr
	RemotePort uint16
	UID        uint64
}

func GetAll() ([]Item, error) {
	Group := make([]Item, 0)
	GroupTCP, err := GetTCP()
	if err != nil {
		return nil, err
	}
	Group = append(Group, GroupTCP...)
	GroupUDP, err := GetUDP()
	if err != nil {
		return nil, err
	}
	Group = append(Group, GroupUDP...)
	return Group, nil
}

func GetTCP() ([]Item, error) {
	Group := make([]Item, 0)
	Group4, err := GetTCP4()
	if err != nil {
		return nil, err
	}
	Group = append(Group, Group4...)
	Group6, err := GetTCP6()
	if err != nil {
		return nil, err
	}
	Group = append(Group, Group6...)
	return Group, nil
}

func GetUDP() ([]Item, error) {
	Group := make([]Item, 0)
	Group4, err := GetUDP4()
	if err != nil {
		return nil, err
	}
	Group = append(Group, Group4...)
	Group6, err := GetUDP6()
	if err != nil {
		return nil, err
	}
	Group = append(Group, Group6...)
	return Group, nil
}

func GetTCP4() ([]Item, error) {
	Result4, err := ioutil.ReadFile(PathTCP4)
	if err != nil {
		return nil, err
	}
	Group := make([]Item, 0)
	for k, v := range bytes.Split(Result4, []byte("\n")) {
		if k == 0 {
			continue
		}
		V := strings.Split(strings.Trim(string(v), " "), " ")
		if len(V) < 2 {
			continue
		}
		LocalAddress := V[1]
		RemoteAddress := V[2]
		UIDStr := V[9]
		UID, _ := strconv.ParseUint(UIDStr, 16, 64)
		LocalIP, _ := parseIPv4(strings.Split(LocalAddress, ":")[0])
		RemoteIP, _ := parseIPv4(strings.Split(RemoteAddress, ":")[0])
		LocalPort, _ := parsePort(strings.Split(LocalAddress, ":")[1])
		RemotePort, _ := parsePort(strings.Split(RemoteAddress, ":")[1])
		item := Item{
			Protocol:   TCP,
			LocalIP:    LocalIP,
			LocalPort:  LocalPort,
			RemoteIP:   RemoteIP,
			RemotePort: RemotePort,
			UID:        UID,
		}
		Group = append(Group, item)
	}
	return Group, nil
}

func GetUDP4() ([]Item, error) {
	Result4, err := ioutil.ReadFile(PathUDP4)
	if err != nil {
		return nil, err
	}
	Group := make([]Item, 0)
	for k, v := range bytes.Split(Result4, []byte("\n")) {
		if k == 0 {
			continue
		}
		V := strings.Split(strings.Trim(string(v), " "), " ")
		if len(V) < 2 {
			continue
		}
		LocalAddress := V[1]
		RemoteAddress := V[2]
		UIDStr := V[9]
		UID, _ := strconv.ParseUint(UIDStr, 16, 64)
		LocalIP, _ := parseIPv4(strings.Split(LocalAddress, ":")[0])
		RemoteIP, _ := parseIPv4(strings.Split(RemoteAddress, ":")[0])
		LocalPort, _ := parsePort(strings.Split(LocalAddress, ":")[1])
		RemotePort, _ := parsePort(strings.Split(RemoteAddress, ":")[1])
		item := Item{
			Protocol:   UDP,
			LocalIP:    LocalIP,
			LocalPort:  LocalPort,
			RemoteIP:   RemoteIP,
			RemotePort: RemotePort,
			UID:        UID,
		}
		Group = append(Group, item)
	}
	return Group, nil
}

func GetTCP6() ([]Item, error) {
	Result6, err := ioutil.ReadFile(PathTCP6)
	if err != nil {
		return nil, err
	}
	Group := make([]Item, 0)
	for k, v := range bytes.Split(Result6, []byte("\n")) {
		if k == 0 {
			continue
		}
		V := strings.Split(strings.Trim(string(v), " "), " ")
		if len(V) < 2 {
			continue
		}
		LocalAddress := V[1]
		RemoteAddress := V[2]
		UIDStr := V[8]
		UID, _ := strconv.ParseUint(UIDStr, 16, 64)
		LocalIP, _ := parseIPv6(strings.Split(LocalAddress, ":")[0])
		RemoteIP, _ := parseIPv6(strings.Split(RemoteAddress, ":")[0])
		LocalPort, _ := parsePort(strings.Split(LocalAddress, ":")[1])
		RemotePort, _ := parsePort(strings.Split(RemoteAddress, ":")[1])
		item := Item{
			Protocol:   TCP,
			LocalIP:    LocalIP,
			LocalPort:  LocalPort,
			RemoteIP:   RemoteIP,
			RemotePort: RemotePort,
			UID:        UID,
		}
		Group = append(Group, item)
	}
	return Group, nil
}

func GetUDP6() ([]Item, error) {
	Result6, err := ioutil.ReadFile(PathUDP6)
	if err != nil {
		return nil, err
	}
	Group := make([]Item, 0)
	for k, v := range bytes.Split(Result6, []byte("\n")) {
		if k == 0 {
			continue
		}
		V := strings.Split(strings.Trim(string(v), " "), " ")
		if len(V) < 2 {
			continue
		}
		LocalAddress := V[1]
		RemoteAddress := V[2]
		UIDStr := V[8]
		UID, _ := strconv.ParseUint(UIDStr, 16, 64)
		LocalIP, _ := parseIPv6(strings.Split(LocalAddress, ":")[0])
		RemoteIP, _ := parseIPv6(strings.Split(RemoteAddress, ":")[0])
		LocalPort, _ := parsePort(strings.Split(LocalAddress, ":")[1])
		RemotePort, _ := parsePort(strings.Split(RemoteAddress, ":")[1])
		item := Item{
			Protocol:   UDP,
			LocalIP:    LocalIP,
			LocalPort:  LocalPort,
			RemoteIP:   RemoteIP,
			RemotePort: RemotePort,
			UID:        UID,
		}
		Group = append(Group, item)
	}
	return Group, nil
}

func parsePort(s string) (uint16, error) {
	PortUint64, err := strconv.ParseUint(s, 16, 16)
	if err != nil {
		return 0, err
	}
	Port := uint16(PortUint64)
	return Port, nil
}

func parseIPv4(s string) (netip.Addr, error) {
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		panic(err)
	}
	ip := make(net.IP, net.IPv4len)
	binary.LittleEndian.PutUint32(ip, uint32(v))
	return netip.ParseAddr(ip.String())
}

func parseIPv6(s string) (netip.Addr, error) {
	ip := make(net.IP, net.IPv6len)
	const grpLen = 4
	i, j := 0, 4
	for len(s) != 0 {
		grp := s[0:8]
		u, err := strconv.ParseUint(grp, 16, 32)
		binary.LittleEndian.PutUint32(ip[i:j], uint32(u))
		if err != nil {
			return netip.Addr{}, err
		}
		i, j = i+grpLen, j+grpLen
		s = s[8:]
	}
	return netip.ParseAddr(ip.String())
}
