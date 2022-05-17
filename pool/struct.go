package pool

import (
	"net/netip"
	"sync"
	"time"
)

type NetAddrSlice struct {
	IPv4   []netip.Addr
	IPv6   []netip.Addr
	CIDRv4 []netip.Prefix
	CIDRv6 []netip.Prefix
}

type NetAddrMap struct {
	IPv4   map[netip.Addr]interface{}
	IPv6   map[netip.Addr]interface{}
	CIDRv4 map[netip.Prefix]interface{}
	CIDRv6 map[netip.Prefix]interface{}
}

type Receive struct {
	Data NetAddrSlice
	TTL  time.Duration
}

type Send struct {
	Add NetAddrSlice
	Del NetAddrSlice
}

func diffAddr(SliceA, SliceB []netip.Addr) ([]netip.Addr, []netip.Addr, bool) {
	if SliceA == nil || SliceB == nil {
		if SliceA == nil && SliceB != nil {
			return SliceB, []netip.Addr{}, true
		}
		if SliceA != nil && SliceB == nil {
			return []netip.Addr{}, SliceA, true
		}
		if SliceA == nil && SliceB == nil {
			return []netip.Addr{}, []netip.Addr{}, false
		}
	}
	if len(SliceA) <= 0 || len(SliceB) <= 0 {
		if len(SliceA) > 0 && len(SliceB) <= 0 {
			return []netip.Addr{}, SliceA, true
		}
		if len(SliceA) <= 0 && len(SliceB) > 0 {
			return SliceB, []netip.Addr{}, true
		}
		if len(SliceA) <= 0 && len(SliceB) <= 0 {
			return []netip.Addr{}, []netip.Addr{}, false
		}
	}
	T := make(map[netip.Addr]int)
	TA := make(map[netip.Addr]int)
	TB := make(map[netip.Addr]int)
	SliceAdd := make([]netip.Addr, 0)
	SliceDel := make([]netip.Addr, 0)
	Change := false
	for _, v := range SliceA {
		T[v]++
		TA[v]++
	}
	for _, v := range SliceB {
		T[v]++
		TB[v]++
	}
	for k := range T {
		_, ok1 := TA[k]
		_, ok2 := TB[k]
		if ok1 && ok2 {
			continue
		}
		if ok1 && !ok2 {
			SliceDel = append(SliceDel, k)
			Change = true
		}
		if !ok1 && ok2 {
			SliceAdd = append(SliceAdd, k)
			Change = true
		}
	}
	return SliceAdd, SliceDel, Change
}

func diffPrefix(SliceA, SliceB []netip.Prefix) ([]netip.Prefix, []netip.Prefix, bool) {
	if SliceA == nil || SliceB == nil {
		if SliceA == nil && SliceB != nil {
			return SliceB, []netip.Prefix{}, true
		}
		if SliceA != nil && SliceB == nil {
			return []netip.Prefix{}, SliceA, true
		}
		if SliceA == nil && SliceB == nil {
			return []netip.Prefix{}, []netip.Prefix{}, false
		}
	}
	if len(SliceA) <= 0 || len(SliceB) <= 0 {
		if len(SliceA) > 0 && len(SliceB) <= 0 {
			return []netip.Prefix{}, SliceA, true
		}
		if len(SliceA) <= 0 && len(SliceB) > 0 {
			return SliceB, []netip.Prefix{}, true
		}
		if len(SliceA) <= 0 && len(SliceB) <= 0 {
			return []netip.Prefix{}, []netip.Prefix{}, false
		}
	}
	T := make(map[netip.Prefix]int)
	TA := make(map[netip.Prefix]int)
	TB := make(map[netip.Prefix]int)
	SliceAdd := make([]netip.Prefix, 0)
	SliceDel := make([]netip.Prefix, 0)
	Change := false
	for _, v := range SliceA {
		T[v]++
		TA[v]++
	}
	for _, v := range SliceB {
		T[v]++
		TB[v]++
	}
	for k := range T {
		_, ok1 := TA[k]
		_, ok2 := TB[k]
		if ok1 && ok2 {
			continue
		}
		if ok1 && !ok2 {
			SliceDel = append(SliceDel, k)
			Change = true
		}
		if !ok1 && ok2 {
			SliceAdd = append(SliceAdd, k)
			Change = true
		}
	}
	return SliceAdd, SliceDel, Change
}

func diffNetAddrSlice(SliceA, SliceB NetAddrSlice) (Send, bool) {
	var (
		IPv4Add, IPv6Add, IPv4Del, IPv6Del         []netip.Addr
		CIDRv4Add, CIDRv6Add, CIDRv4Del, CIDRv6Del []netip.Prefix
		Check                                      bool
	)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		var check bool
		IPv4Add, IPv4Del, check = diffAddr(SliceA.IPv4, SliceB.IPv4)
		if check {
			Check = check
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		var check bool
		IPv6Add, IPv6Del, check = diffAddr(SliceA.IPv6, SliceB.IPv6)
		if check {
			Check = check
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		var check bool
		CIDRv4Add, CIDRv4Del, check = diffPrefix(SliceA.CIDRv4, SliceB.CIDRv4)
		if check {
			Check = check
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		var check bool
		CIDRv6Add, CIDRv6Del, check = diffPrefix(SliceA.CIDRv6, SliceB.CIDRv6)
		if check {
			Check = check
		}
	}()
	wg.Wait()
	return Send{
		Add: NetAddrSlice{
			IPv4:   IPv4Add,
			IPv6:   IPv6Add,
			CIDRv4: CIDRv4Add,
			CIDRv6: CIDRv6Add,
		},
		Del: NetAddrSlice{
			IPv4:   IPv4Del,
			IPv6:   IPv6Del,
			CIDRv4: CIDRv4Del,
			CIDRv6: CIDRv6Del,
		},
	}, Check
}

func DiffNetAddrSlice(SliceA, SliceB NetAddrSlice) (Send, bool) {
	return diffNetAddrSlice(SliceA, SliceB)
}
