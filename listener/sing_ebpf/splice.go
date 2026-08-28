//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"io"
	"net"
	"reflect"
	"strings"
	"time"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
	"github.com/metacubex/mihomo/common/pool"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/mihomo/log"

	E "github.com/metacubex/sing/common/exceptions"
	N "github.com/metacubex/sing/common/network"

	"golang.org/x/sys/unix"
)

// prepareTCPSplice prepares and attaches the kernel splice backend when the
// tcp-splice option is enabled. A nil return means the userspace copy path
// stays in charge.
func (i *Inbound) prepareTCPSplice() error {
	if !i.tcpSplice {
		return nil
	}
	spliceBackend, err := ECommon.PrepareSplice()
	if err == nil {
		err = spliceBackend.Attach()
	}
	if err != nil {
		if spliceBackend != nil {
			_ = spliceBackend.Close()
		}
		log.Infoln("[EBPF] experimental direct TCP splice unavailable; using userspace copy: %s", err.Error())
		i.tcpSplice = false
		return nil
	}
	i.tcpSpliceBackend = spliceBackend
	log.Infoln("[EBPF] experimental direct TCP splice ready")
	return nil
}

func (i *Inbound) closeTCPSplice() {
	if i.tcpSpliceBackend == nil {
		return
	}
	if statistics := i.tcpSpliceBackend.Statistics(); statistics.Attempts > 0 {
		log.Infoln("[EBPF] TCP splice statistics: attempts=%d, activated=%d, active_pairs=%d, fallbacks=%d",
			statistics.Attempts, statistics.Activated, statistics.ActivePairs, statistics.Fallbacks)
	}
	_ = i.tcpSpliceBackend.Close()
	i.tcpSpliceBackend = nil
}

// tryHandleSplice attempts to hand an already-routed DIRECT connection pair to
// the kernel splice data plane. It is invoked from the tunnel core right
// before the userspace relay starts; returning false keeps both connections
// owned by the relay.
func (i *Inbound) tryHandleSplice(local, remote net.Conn, proxyType C.AdapterType) bool {
	backend := i.tcpSpliceBackend
	if backend == nil {
		return false
	}
	if proxyType != C.Direct {
		backend.RecordFallback(ECommon.SpliceFallbackNotDirect)
		return false
	}
	localTCP := spliceTCPConn(local)
	remoteTCP := spliceTCPConn(remote)
	if localTCP == nil || remoteTCP == nil {
		backend.RecordFallback(ECommon.SpliceFallbackNotPlainTCP)
		return false
	}
	if err := flushSpliceCachedData(local, remoteTCP); err != nil {
		backend.RecordFallback(ECommon.SpliceFallbackCachedData)
		log.Debugln("[EBPF] TCP splice fallback while flushing cached data: %s", err.Error())
		return false
	}
	if err := drainSpliceReceiveQueue(localTCP, remoteTCP); err != nil {
		backend.RecordFallback(ECommon.SpliceFallbackInboundQueue)
		log.Debugln("[EBPF] TCP splice fallback while draining inbound data: %s", err.Error())
		return false
	}
	if err := drainSpliceReceiveQueue(remoteTCP, localTCP); err != nil {
		backend.RecordFallback(ECommon.SpliceFallbackOutboundQueue)
		log.Debugln("[EBPF] TCP splice fallback while draining outbound data: %s", err.Error())
		return false
	}
	pair, err := backend.BeginPair(localTCP, remoteTCP, nil, nil)
	if err != nil {
		log.Debugln("[EBPF] TCP splice fallback while publishing pair: %s", err.Error())
		return false
	}
	if err = pair.Activate(); err != nil {
		backend.Abort(pair)
		log.Debugln("[EBPF] TCP splice fallback while activating pair: %s", err.Error())
		return false
	}
	return true
}

const spliceConnChainLimit = 16

func walkSpliceConn(conn net.Conn, visit func(net.Conn) bool) bool {
	for depth := 0; conn != nil; depth++ {
		if depth >= spliceConnChainLimit {
			return false
		}
		if visit(conn) {
			return true
		}
		if _, isTCP := conn.(*net.TCPConn); !isTCP {
			reader, readerOK := conn.(interface{ ReaderReplaceable() bool })
			writer, writerOK := conn.(interface{ WriterReplaceable() bool })
			if !readerOK || !writerOK || !reader.ReaderReplaceable() || !writer.WriterReplaceable() {
				break
			}
		}
		if upstream, loaded := conn.(interface{ Upstream() any }); loaded {
			if next, nextLoaded := upstream.Upstream().(net.Conn); nextLoaded && next != nil && next != conn {
				conn = next
				continue
			}
		}
		if netConn, loaded := conn.(interface{ NetConn() net.Conn }); loaded {
			if next := netConn.NetConn(); next != nil && next != conn {
				conn = next
				continue
			}
		}
		break
	}
	return true
}

func spliceTCPConn(conn net.Conn) *net.TCPConn {
	var tcpConn *net.TCPConn
	opaque := false
	complete := walkSpliceConn(conn, func(current net.Conn) bool {
		if isOpaqueSpliceConn(current) {
			opaque = true
			return true
		}
		if tcp, loaded := current.(*net.TCPConn); loaded {
			tcpConn = tcp
			return true
		}
		return false
	})
	if !complete || opaque {
		return nil
	}
	return tcpConn
}

func isOpaqueSpliceConn(conn net.Conn) bool {
	name := strings.ToLower(reflect.TypeOf(conn).String())
	for _, marker := range []string{"tls.", "utls.", "tlsfragment.", "tlsspoof.", "shadowsocks.", "vmess.", "vless.", "trojan.", "shadowtls.", "anytls.", "hysteria.", "tuic.", "naive.", "reality.", "mux.", "smux.", "yamux."} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

func flushSpliceCachedData(local net.Conn, remote *net.TCPConn) error {
	var flushErr error
	complete := walkSpliceConn(local, func(current net.Conn) bool {
		cached, loaded := current.(N.CachedReader)
		if !loaded {
			return false
		}
		buffer := cached.ReadCached()
		if buffer == nil {
			return false
		}
		defer buffer.Release()
		if buffer.Len() == 0 {
			return false
		}
		_, flushErr = remote.Write(buffer.Bytes())
		return flushErr != nil
	})
	if flushErr != nil {
		return flushErr
	}
	if !complete {
		return E.New("TCP connection wrapper chain is too deep")
	}
	return nil
}

func drainSpliceReceiveQueue(source, destination *net.TCPConn) error {
	const maxRounds = 32
	var buffer []byte
	defer func() {
		if buffer != nil {
			pool.Put(buffer)
		}
	}()
	for range maxRounds {
		queued, err := spliceReceiveQueueSize(source)
		if err != nil || queued == 0 {
			return err
		}
		if queued > 64*1024 {
			queued = 64 * 1024
		}
		if len(buffer) < queued {
			if buffer != nil {
				pool.Put(buffer)
			}
			buffer = pool.Get(queued)
		}
		payload := buffer[:queued]
		_ = source.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		read, readErr := source.Read(payload)
		_ = source.SetReadDeadline(time.Time{})
		if read > 0 {
			if _, err = destination.Write(payload[:read]); err != nil {
				return err
			}
		}
		if readErr != nil {
			if timeout, loaded := readErr.(net.Error); loaded && timeout.Timeout() && read > 0 {
				continue
			}
			if readErr == io.EOF && read > 0 {
				return nil
			}
			return readErr
		}
	}
	queued, err := spliceReceiveQueueSize(source)
	if err != nil {
		return err
	}
	if queued != 0 {
		return E.New("TCP receive queue remained busy")
	}
	return nil
}

func spliceReceiveQueueSize(conn *net.TCPConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var queued int
	var controlErr error
	err = raw.Control(func(fd uintptr) {
		queued, controlErr = unix.IoctlGetInt(int(fd), unix.TIOCINQ)
	})
	if err != nil {
		return 0, err
	}
	return queued, controlErr
}
