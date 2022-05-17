package pool

import (
	"github.com/yaotthaha/cachemap"
	"net/netip"
	"runtime"
	"sync"
	"time"
)

type poolInterface interface {
	NewPool()
}

type poolWrapper struct {
	*pool
}

type pool struct {
	IPv4       cachemap.CacheMap
	IPv6       cachemap.CacheMap
	CIDRv4     cachemap.CacheMap
	CIDRv6     cachemap.CacheMap
	Cache      NetAddrSlice
	RvChan     *chan Receive
	SdChan     *chan Send
	StopChan   chan struct{}
	stopStatus bool
}

type Pool = *poolWrapper

func (p *pool) run() {
	CallGlobal := make(chan struct{}, 1024)
	Call := make(chan struct{}, 16)
	Lock := sync.Mutex{}
	defer close(CallGlobal)
	defer close(Call)
	WG := sync.WaitGroup{}
	WG.Add(1)
	go func() {
		defer WG.Done()
		for {
			select {
			case r := <-*p.RvChan:
				Lock.Lock()
				wg := sync.WaitGroup{}
				if r.Data.IPv4 != nil {
					if len(r.Data.IPv4) > 0 {
						wg.Add(1)
						go func() {
							defer wg.Done()
							for _, v := range r.Data.IPv4 {
								err := p.IPv4.Add(v, nil, r.TTL, func(item cachemap.CacheItem) {
									CallGlobal <- struct{}{}
								})
								if err != nil {
									_ = p.IPv4.SetTTL(v, r.TTL, true)
								}
							}
						}()
					}
				}
				if r.Data.IPv6 != nil {
					if len(r.Data.IPv6) > 0 {
						wg.Add(1)
						go func() {
							defer wg.Done()
							for _, v := range r.Data.IPv6 {
								err := p.IPv6.Add(v, nil, r.TTL, func(item cachemap.CacheItem) {
									CallGlobal <- struct{}{}
								})
								if err != nil {
									_ = p.IPv6.SetTTL(v, r.TTL, true)
								}
							}
						}()
					}
				}
				if r.Data.CIDRv4 != nil {
					if len(r.Data.CIDRv4) > 0 {
						wg.Add(1)
						go func() {
							defer wg.Done()
							for _, v := range r.Data.CIDRv4 {
								err := p.CIDRv4.Add(v, nil, r.TTL, func(item cachemap.CacheItem) {
									CallGlobal <- struct{}{}
								})
								if err != nil {
									_ = p.CIDRv4.SetTTL(v, r.TTL, true)
								}
							}
						}()
					}
				}
				if r.Data.CIDRv6 != nil {
					if len(r.Data.CIDRv6) > 0 {
						wg.Add(1)
						go func() {
							defer wg.Done()
							for _, v := range r.Data.CIDRv6 {
								err := p.CIDRv6.Add(v, nil, r.TTL, func(item cachemap.CacheItem) {
									CallGlobal <- struct{}{}
								})
								if err != nil {
									_ = p.CIDRv6.SetTTL(v, r.TTL, true)
								}
							}
						}()
					}
				}
				wg.Wait()
				Lock.Unlock()
				CallGlobal <- struct{}{}
			case <-p.StopChan:
				return
			}
		}
	}()
	WG.Add(1)
	go func() {
		defer WG.Done()
		for {
			select {
			case <-CallGlobal:
				switch len(CallGlobal) {
				case 0:
				case 1:
					<-time.After(1 * time.Second)
					continue
				default:
					continue
				}
				Call <- struct{}{}
			case <-p.StopChan:
				return
			}
		}
	}()
	WG.Add(1)
	go func() {
		defer WG.Done()
		for {
			select {
			case <-Call:
				wg := sync.WaitGroup{}
				TempCache := NetAddrSlice{
					IPv4:   make([]netip.Addr, 0),
					IPv6:   make([]netip.Addr, 0),
					CIDRv4: make([]netip.Prefix, 0),
					CIDRv6: make([]netip.Prefix, 0),
				}
				Lock.Lock()
				wg.Add(1)
				go func() {
					defer wg.Done()
					p.IPv4.Foreach(func(item cachemap.CacheItem) {
						TempCache.IPv4 = append(TempCache.IPv4, item.Key.(netip.Addr))
					})
				}()
				wg.Add(1)
				go func() {
					defer wg.Done()
					p.IPv6.Foreach(func(item cachemap.CacheItem) {
						TempCache.IPv6 = append(TempCache.IPv6, item.Key.(netip.Addr))
					})
				}()
				wg.Add(1)
				go func() {
					defer wg.Done()
					p.CIDRv4.Foreach(func(item cachemap.CacheItem) {
						TempCache.CIDRv4 = append(TempCache.CIDRv4, item.Key.(netip.Prefix))
					})
				}()
				wg.Add(1)
				go func() {
					defer wg.Done()
					p.CIDRv6.Foreach(func(item cachemap.CacheItem) {
						TempCache.CIDRv6 = append(TempCache.CIDRv6, item.Key.(netip.Prefix))
					})
				}()
				Send, Change := diffNetAddrSlice(p.Cache, TempCache)
				p.Cache = TempCache
				if Change {
					*p.SdChan <- Send
				}
				Lock.Unlock()
			case <-p.StopChan:
				return
			}
		}
	}()
	WG.Wait()
}

func newPool(RvChan *chan Receive, SdChan *chan Send) *pool {
	p := &pool{
		IPv4:   cachemap.NewCacheMap(),
		IPv6:   cachemap.NewCacheMap(),
		CIDRv4: cachemap.NewCacheMap(),
		CIDRv6: cachemap.NewCacheMap(),
		Cache: NetAddrSlice{
			IPv4:   make([]netip.Addr, 0),
			IPv6:   make([]netip.Addr, 0),
			CIDRv4: make([]netip.Prefix, 0),
			CIDRv6: make([]netip.Prefix, 0),
		},
		RvChan:     RvChan,
		SdChan:     SdChan,
		StopChan:   make(chan struct{}),
		stopStatus: false,
	}
	return p
}

func (p *pool) stop() {
	if !p.stopStatus {
		p.StopChan <- struct{}{}
		p.IPv4.Stop()
		p.IPv6.Stop()
		p.CIDRv4.Stop()
		p.CIDRv6.Stop()
		p.stopStatus = true
	}
}

func NewPool(RvChan *chan Receive, SdChan *chan Send) Pool {
	pw := &poolWrapper{newPool(RvChan, SdChan)}
	go pw.run()
	runtime.SetFinalizer(pw, (*poolWrapper).stop)
	return pw
}

func (pw *poolWrapper) Stop() {
	pw.stop()
}
