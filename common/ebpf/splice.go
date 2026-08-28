//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"

	E "github.com/metacubex/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	spliceSocketCapacity  = 8192
	splicePairCapacity    = spliceSocketCapacity / 2
	spliceKernelStatCount = 4
	spliceFallbackCount   = 10
)

type SpliceFallbackReason uint8

const (
	SpliceFallbackNotDirect SpliceFallbackReason = iota
	SpliceFallbackTransformed
	SpliceFallbackNotPlainTCP
	SpliceFallbackCachedData
	SpliceFallbackInboundQueue
	SpliceFallbackOutboundQueue
	SpliceFallbackPublish
	SpliceFallbackActivate
	SpliceFallbackUnavailable
	SpliceFallbackPowerReportActive
)

var spliceFallbackNames = [...]string{
	"not_direct", "transformed", "not_plain_tcp", "cached_data", "inbound_queue",
	"outbound_queue", "publish", "activate", "unavailable",
	"power_report_active",
}

type spliceKey struct {
	Family     uint8
	Protocol   uint8
	LocalPort  uint16
	RemotePort uint16
	Reserved   uint16
	LocalAddr  [16]byte
	RemoteAddr [16]byte
}

type splicePeerValue struct {
	Key   spliceKey
	Bytes uint64
}

type SpliceStatistics struct {
	AttachmentMode        string            `json:"attachment_mode,omitempty"`
	Attempts              uint64            `json:"attempts"`
	Activated             uint64            `json:"activated"`
	Fallbacks             uint64            `json:"fallbacks"`
	Released              uint64            `json:"released"`
	ActivePairs           uint64            `json:"active_pairs"`
	RedirectSuccesses     uint64            `json:"redirect_successes"`
	RedirectFailures      uint64            `json:"redirect_failures"`
	PeerMisses            uint64            `json:"peer_misses"`
	KeyErrors             uint64            `json:"key_errors"`
	AccountedUpload       uint64            `json:"accounted_upload"`
	AccountedDownload     uint64            `json:"accounted_download"`
	FallbackReasons       map[string]uint64 `json:"fallback_reasons,omitempty"`
	KernelStatisticsError string            `json:"kernel_statistics_error,omitempty"`
}

type SpliceBackend struct {
	access            sync.Mutex
	maps              map[string]*CiliumEBPF.Map
	programs          []*CiliumEBPF.Program
	attached          bool
	attachmentMode    string
	links             []link.Link
	closed            bool
	pairs             map[*SplicePair]struct{}
	watcher           *spliceWatcher
	attempts          atomic.Uint64
	activated         atomic.Uint64
	fallbacks         atomic.Uint64
	released          atomic.Uint64
	accountedUpload   atomic.Uint64
	accountedDownload atomic.Uint64
	fallbackReason    [spliceFallbackCount]atomic.Uint64
}

type SplicePair struct {
	access    sync.Mutex
	backend   *SpliceBackend
	leftKey   spliceKey
	rightKey  spliceKey
	left      *net.TCPConn
	right     *net.TCPConn
	onClose   func(error)
	account   func(upload, download int64)
	activated bool
	released  bool
}

func PrepareSplice() (*SpliceBackend, error) {
	_ = raiseMemlockLimit()
	maps, err := loadObjectMaps(loadSplice, map[string]mapSpecOverride{
		"splice_sockets": {name: "sb_splice_sock", mapType: CiliumEBPF.SockHash, maxEntries: spliceSocketCapacity},
		"splice_peers":   {name: "sb_splice_peer", mapType: CiliumEBPF.Hash, maxEntries: spliceSocketCapacity, flags: bpfFlagNoPrealloc},
		"splice_stats":   {name: "sb_splice_stat", mapType: CiliumEBPF.PerCPUArray, maxEntries: spliceKernelStatCount},
	})
	if err != nil {
		return nil, err
	}
	programs, err := loadObjectPrograms(loadSplice, maps, []programSelection{
		{section: "sk_skb/stream_parser", name: "sb_splice_parse"},
		{section: "sk_skb/stream_verdict", name: "sb_splice_redir"},
	})
	if err != nil {
		_ = closeMaps(maps)
		return nil, err
	}
	backend := &SpliceBackend{
		maps:     maps,
		programs: programs,
		pairs:    make(map[*SplicePair]struct{}),
	}
	backend.watcher, err = newSpliceWatcher()
	if err != nil {
		_ = closePrograms(programs)
		_ = closeMaps(maps)
		return nil, E.Cause(err, "create TCP splice watcher")
	}
	return backend, nil
}

func (b *SpliceBackend) Attach() error {
	if b == nil {
		return errBackendClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.closed || b.maps == nil {
		return errBackendClosed
	}
	if b.attached {
		return nil
	}
	target := b.maps["splice_sockets"].FD()
	parserLink, parserLinkErr := link.AttachRawLink(link.RawLinkOptions{
		Target: target, Program: b.programs[0], Attach: CiliumEBPF.AttachSkSKBStreamParser,
	})
	if parserLinkErr == nil {
		verdictLink, verdictLinkErr := link.AttachRawLink(link.RawLinkOptions{
			Target: target, Program: b.programs[1], Attach: CiliumEBPF.AttachSkSKBStreamVerdict,
		})
		if verdictLinkErr == nil {
			b.links = []link.Link{parserLink, verdictLink}
			b.attachmentMode = "link"
			b.attached = true
			return nil
		}
		_ = parserLink.Close()
	}
	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  target,
		Program: b.programs[0],
		Attach:  CiliumEBPF.AttachSkSKBStreamParser,
	}); err != nil {
		return E.Cause(err, "attach TCP splice stream parser")
	}
	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  target,
		Program: b.programs[1],
		Attach:  CiliumEBPF.AttachSkSKBStreamVerdict,
	}); err != nil {
		_ = link.RawDetachProgram(link.RawDetachProgramOptions{
			Target: target, Program: b.programs[0], Attach: CiliumEBPF.AttachSkSKBStreamParser,
		})
		return E.Cause(err, "attach TCP splice stream verdict")
	}
	b.attachmentMode = "raw"
	b.attached = true
	return nil
}

func (b *SpliceBackend) BeginPair(left, right *net.TCPConn, onClose func(error), account func(upload, download int64)) (*SplicePair, error) {
	if b == nil || left == nil || right == nil {
		return nil, E.New("invalid TCP splice pair")
	}
	b.attempts.Add(1)
	leftKey, err := makeSpliceKey(left)
	if err != nil {
		b.RecordFallback(SpliceFallbackPublish)
		return nil, E.Cause(err, "build inbound TCP splice key")
	}
	rightKey, err := makeSpliceKey(right)
	if err != nil {
		b.RecordFallback(SpliceFallbackPublish)
		return nil, E.Cause(err, "build outbound TCP splice key")
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.closed || !b.attached || len(b.pairs) >= splicePairCapacity {
		b.RecordFallback(SpliceFallbackUnavailable)
		return nil, E.New("TCP splice backend is unavailable or full")
	}
	peerMap := b.maps["splice_peers"]
	leftPeer := splicePeerValue{Key: rightKey}
	rightPeer := splicePeerValue{Key: leftKey}
	if err = peerMap.Update(&leftKey, &leftPeer, CiliumEBPF.UpdateNoExist); err != nil {
		b.RecordFallback(SpliceFallbackPublish)
		return nil, E.Cause(err, "publish inbound TCP splice peer")
	}
	if err = peerMap.Update(&rightKey, &rightPeer, CiliumEBPF.UpdateNoExist); err != nil {
		_ = peerMap.Delete(&leftKey)
		b.RecordFallback(SpliceFallbackPublish)
		return nil, E.Cause(err, "publish outbound TCP splice peer")
	}
	pair := &SplicePair{backend: b, leftKey: leftKey, rightKey: rightKey, left: left, right: right, onClose: onClose, account: account}
	b.pairs[pair] = struct{}{}
	return pair, nil
}

func (p *SplicePair) Activate() error {
	if p == nil || p.backend == nil {
		return E.New("invalid TCP splice pair")
	}
	p.access.Lock()
	defer p.access.Unlock()
	if p.released {
		return E.New("TCP splice pair is released")
	}
	if p.activated {
		return nil
	}
	b := p.backend
	b.access.Lock()
	defer b.access.Unlock()
	if b.closed || !b.attached {
		return errBackendClosed
	}
	leftFD, err := tcpConnFD(p.left)
	if err != nil {
		return err
	}
	rightFD, err := tcpConnFD(p.right)
	if err != nil {
		return err
	}
	sockets := b.maps["splice_sockets"]
	if err = sockets.Update(&p.leftKey, &leftFD, CiliumEBPF.UpdateNoExist); err != nil {
		return E.Cause(err, "activate inbound TCP splice socket")
	}
	if err = sockets.Update(&p.rightKey, &rightFD, CiliumEBPF.UpdateNoExist); err != nil {
		_ = sockets.Delete(&p.leftKey)
		return E.Cause(err, "activate outbound TCP splice socket")
	}
	if err = b.watcher.add(p, int32(leftFD), int32(rightFD)); err != nil {
		_ = sockets.Delete(&p.leftKey)
		_ = sockets.Delete(&p.rightKey)
		return E.Cause(err, "watch TCP splice pair")
	}
	p.activated = true
	b.activated.Add(1)
	return nil
}

func (p *SplicePair) Release() error {
	if p == nil {
		return nil
	}
	p.access.Lock()
	if p.released {
		p.access.Unlock()
		return nil
	}
	p.released = true
	b := p.backend
	activated := p.activated
	onClose := p.onClose
	account := p.account
	p.onClose = nil
	p.account = nil
	p.access.Unlock()
	var releaseErr error
	if b != nil {
		b.access.Lock()
		if b.watcher != nil {
			b.watcher.remove(p)
		}
		if b.maps != nil {
			releaseErr = ignoreSpliceDeleteError(b.maps["splice_sockets"].Delete(&p.leftKey))
			releaseErr = E.Errors(releaseErr, ignoreSpliceDeleteError(b.maps["splice_sockets"].Delete(&p.rightKey)))
			var leftPeer, rightPeer splicePeerValue
			leftErr := b.maps["splice_peers"].Lookup(&p.leftKey, &leftPeer)
			rightErr := b.maps["splice_peers"].Lookup(&p.rightKey, &rightPeer)
			if leftErr == nil && rightErr == nil && account != nil {
				account(int64(leftPeer.Bytes), int64(rightPeer.Bytes))
				b.accountedUpload.Add(leftPeer.Bytes)
				b.accountedDownload.Add(rightPeer.Bytes)
			}
			releaseErr = E.Errors(releaseErr, ignoreSpliceDeleteError(b.maps["splice_peers"].Delete(&p.leftKey)))
			releaseErr = E.Errors(releaseErr, ignoreSpliceDeleteError(b.maps["splice_peers"].Delete(&p.rightKey)))
		}
		delete(b.pairs, p)
		b.released.Add(1)
		b.access.Unlock()
	}
	if activated {
		_ = p.left.Close()
		_ = p.right.Close()
	}
	if onClose != nil {
		onClose(releaseErr)
	}
	return releaseErr
}

func ignoreSpliceDeleteError(err error) error {
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

func (b *SpliceBackend) Abort(pair *SplicePair) {
	if pair == nil {
		return
	}
	pair.access.Lock()
	pair.activated = false
	pair.onClose = nil
	pair.access.Unlock()
	_ = pair.Release()
	b.RecordFallback(SpliceFallbackActivate)
}

func (b *SpliceBackend) Statistics() SpliceStatistics {
	if b == nil {
		return SpliceStatistics{}
	}
	b.access.Lock()
	defer b.access.Unlock()
	active := len(b.pairs)
	statistics := SpliceStatistics{
		Attempts: b.attempts.Load(), Activated: b.activated.Load(), Fallbacks: b.fallbacks.Load(),
		Released: b.released.Load(), ActivePairs: uint64(active), AttachmentMode: b.attachmentMode,
		AccountedUpload: b.accountedUpload.Load(), AccountedDownload: b.accountedDownload.Load(),
	}
	for index, name := range spliceFallbackNames {
		value := b.fallbackReason[index].Load()
		if value == 0 {
			continue
		}
		if statistics.FallbackReasons == nil {
			statistics.FallbackReasons = make(map[string]uint64)
		}
		statistics.FallbackReasons[name] = value
	}
	var values [spliceKernelStatCount]uint64
	if b.maps == nil || b.maps["splice_stats"] == nil {
		return statistics
	}
	for index := range values {
		key := uint32(index)
		var perCPU []uint64
		if err := b.maps["splice_stats"].Lookup(&key, &perCPU); err != nil {
			statistics.KernelStatisticsError = err.Error()
			return statistics
		}
		for _, value := range perCPU {
			values[index] += value
		}
	}
	statistics.RedirectSuccesses = values[0]
	statistics.RedirectFailures = values[1]
	statistics.PeerMisses = values[2]
	statistics.KeyErrors = values[3]
	return statistics
}

func (b *SpliceBackend) RecordFallback(reason SpliceFallbackReason) {
	if b == nil || int(reason) >= spliceFallbackCount {
		return
	}
	b.fallbacks.Add(1)
	b.fallbackReason[reason].Add(1)
}

func (b *SpliceBackend) Close() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	if b.closed {
		b.access.Unlock()
		return nil
	}
	b.closed = true
	pairs := make([]*SplicePair, 0, len(b.pairs))
	for pair := range b.pairs {
		pairs = append(pairs, pair)
	}
	b.access.Unlock()
	for _, pair := range pairs {
		_ = pair.Release()
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.watcher != nil {
		b.watcher.close()
		b.watcher = nil
	}
	var closeErr error
	if len(b.links) > 0 {
		for index := len(b.links) - 1; index >= 0; index-- {
			closeErr = E.Errors(closeErr, b.links[index].Close())
		}
		b.links = nil
	} else if b.attached && b.maps != nil && len(b.programs) == 2 {
		target := b.maps["splice_sockets"].FD()
		closeErr = link.RawDetachProgram(link.RawDetachProgramOptions{
			Target: target, Program: b.programs[1], Attach: CiliumEBPF.AttachSkSKBStreamVerdict,
		})
		closeErr = E.Errors(closeErr, link.RawDetachProgram(link.RawDetachProgramOptions{
			Target: target, Program: b.programs[0], Attach: CiliumEBPF.AttachSkSKBStreamParser,
		}))
	}
	closeErr = E.Errors(closeErr, closePrograms(b.programs), closeMaps(b.maps))
	b.programs = nil
	b.maps = nil
	b.attached = false
	b.attachmentMode = ""
	return closeErr
}

func makeSpliceKey(conn *net.TCPConn) (spliceKey, error) {
	var key spliceKey
	key.Protocol = unix.IPPROTO_TCP
	local, localOK := conn.LocalAddr().(*net.TCPAddr)
	remote, remoteOK := conn.RemoteAddr().(*net.TCPAddr)
	if !localOK || !remoteOK || local == nil || remote == nil {
		return key, E.New("invalid TCP endpoints")
	}
	key.LocalPort = uint16(local.Port)
	key.RemotePort = uint16(remote.Port)
	local4, remote4 := local.IP.To4(), remote.IP.To4()
	if local4 != nil && remote4 != nil {
		key.Family = unix.AF_INET
		copy(key.LocalAddr[:4], local4)
		copy(key.RemoteAddr[:4], remote4)
		return key, nil
	}
	if local4 != nil || remote4 != nil {
		return key, E.New("mixed TCP address families")
	}
	local16, remote16 := local.IP.To16(), remote.IP.To16()
	if local16 == nil || remote16 == nil {
		return key, E.New("invalid IPv6 TCP endpoints")
	}
	key.Family = unix.AF_INET6
	copy(key.LocalAddr[:], local16)
	copy(key.RemoteAddr[:], remote16)
	return key, nil
}

func tcpConnFD(conn *net.TCPConn) (uint32, error) {
	var fd uint32
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	err = raw.Control(func(value uintptr) { fd = uint32(value) })
	return fd, err
}

type spliceWatcher struct {
	access sync.Mutex
	epoll  int
	byFD   map[int32]*SplicePair
	byPair map[*SplicePair][2]int32
	half   map[*SplicePair]uint8
	stop   chan struct{}
	done   chan struct{}
}

func newSpliceWatcher() (*spliceWatcher, error) {
	epoll, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, err
	}
	w := &spliceWatcher{
		epoll: epoll, byFD: make(map[int32]*SplicePair), byPair: make(map[*SplicePair][2]int32),
		half: make(map[*SplicePair]uint8), stop: make(chan struct{}), done: make(chan struct{}),
	}
	go w.run()
	return w, nil
}

func (w *spliceWatcher) add(pair *SplicePair, left, right int32) error {
	w.access.Lock()
	defer w.access.Unlock()
	for _, fd := range []int32{left, right} {
		if err := unix.EpollCtl(w.epoll, unix.EPOLL_CTL_ADD, int(fd), &unix.EpollEvent{Events: unix.EPOLLRDHUP | unix.EPOLLHUP | unix.EPOLLERR, Fd: fd}); err != nil {
			if fd == right {
				_ = unix.EpollCtl(w.epoll, unix.EPOLL_CTL_DEL, int(left), nil)
			}
			return err
		}
	}
	w.byFD[left], w.byFD[right] = pair, pair
	w.byPair[pair] = [2]int32{left, right}
	return nil
}

func (w *spliceWatcher) remove(pair *SplicePair) {
	w.access.Lock()
	defer w.access.Unlock()
	fds, loaded := w.byPair[pair]
	if !loaded {
		return
	}
	delete(w.byPair, pair)
	delete(w.half, pair)
	for _, fd := range fds {
		_ = unix.EpollCtl(w.epoll, unix.EPOLL_CTL_DEL, int(fd), nil)
		delete(w.byFD, fd)
	}
}

func (w *spliceWatcher) run() {
	defer close(w.done)
	events := make([]unix.EpollEvent, 64)
	for {
		n, err := unix.EpollWait(w.epoll, events, 1000)
		select {
		case <-w.stop:
			return
		default:
		}
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return
		}
		release := make(map[*SplicePair]struct{}, n)
		type halfClose struct {
			pair *SplicePair
			fd   int32
		}
		var halfCloses []halfClose
		w.access.Lock()
		for index := 0; index < n; index++ {
			fd := events[index].Fd
			pair := w.byFD[fd]
			if pair == nil {
				continue
			}
			if events[index].Events&(unix.EPOLLHUP|unix.EPOLLERR) != 0 {
				release[pair] = struct{}{}
				continue
			}
			if events[index].Events&unix.EPOLLRDHUP != 0 {
				fds := w.byPair[pair]
				bit := uint8(1)
				if fd == fds[1] {
					bit = 2
				}
				if w.half[pair]&bit == 0 {
					w.half[pair] |= bit
					halfCloses = append(halfCloses, halfClose{pair: pair, fd: fd})
				}
				if w.half[pair] == 3 {
					release[pair] = struct{}{}
				}
			}
		}
		w.access.Unlock()
		for _, event := range halfCloses {
			event.pair.propagateHalfClose(event.fd)
		}
		for pair := range release {
			_ = pair.Release()
		}
	}
}

func (p *SplicePair) propagateHalfClose(sourceFD int32) {
	p.access.Lock()
	defer p.access.Unlock()
	leftFD, leftErr := tcpConnFD(p.left)
	if leftErr == nil && int32(leftFD) == sourceFD {
		_ = p.right.CloseWrite()
		return
	}
	_ = p.left.CloseWrite()
}

func (w *spliceWatcher) close() {
	if w == nil {
		return
	}
	close(w.stop)
	_ = unix.Close(w.epoll)
	<-w.done
}
