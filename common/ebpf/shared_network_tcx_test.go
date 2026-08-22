//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type testTCXLink struct {
	closeErrors []error
	closeCount  int
}

func (l *testTCXLink) Close() error {
	l.closeCount++
	if len(l.closeErrors) == 0 {
		return nil
	}
	err := l.closeErrors[0]
	l.closeErrors = l.closeErrors[1:]
	return err
}

func TestTCXReplacementCleanupFailureDoesNotCommit(t *testing.T) {
	cleanupErr := errors.New("close old egress")
	oldIngress := &testTCXLink{}
	oldEgress := &testTCXLink{closeErrors: []error{cleanupErr, nil}}
	attachment := &SharedNetworkTCXAttachment{
		interfaceIndex: 1,
		ingress:        sharedNetworkTCXLink{link: oldIngress, linkID: 1},
		egress:         sharedNetworkTCXLink{link: oldEgress, linkID: 2},
	}
	newIngress := &testTCXLink{}
	newEgress := &testTCXLink{}
	replacement := &SharedNetworkTCXAttachment{
		interfaceIndex: 2,
		ingress:        sharedNetworkTCXLink{link: newIngress, linkID: 3},
		egress:         sharedNetworkTCXLink{link: newEgress, linkID: 4},
	}

	changed, err := attachment.commitReplacementLocked(replacement)
	if changed || !errors.Is(err, cleanupErr) {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if attachment.interfaceIndex != 1 || attachment.ingress.link != nil || attachment.egress.link != oldEgress {
		t.Fatalf("old attachment was incorrectly replaced: %+v", attachment)
	}
	if newIngress.closeCount != 1 || newEgress.closeCount != 1 {
		t.Fatalf("replacement rollback incomplete: ingress=%d egress=%d", newIngress.closeCount, newEgress.closeCount)
	}

	retryIngress := &testTCXLink{}
	retryEgress := &testTCXLink{}
	retry := &SharedNetworkTCXAttachment{
		interfaceIndex: 2,
		ingress:        sharedNetworkTCXLink{link: retryIngress, linkID: 5},
		egress:         sharedNetworkTCXLink{link: retryEgress, linkID: 6},
	}
	changed, err = attachment.commitReplacementLocked(retry)
	if err != nil || !changed {
		t.Fatalf("retry changed=%v err=%v", changed, err)
	}
	if attachment.interfaceIndex != 2 || attachment.ingress.link != retryIngress || attachment.egress.link != retryEgress {
		t.Fatalf("retry replacement was not committed: %+v", attachment)
	}
	if oldIngress.closeCount != 1 || oldEgress.closeCount != 2 {
		t.Fatalf("old cleanup was not retried correctly: ingress=%d egress=%d", oldIngress.closeCount, oldEgress.closeCount)
	}
}

func TestTCXReplacementRollbackFailureIsRetainedForRetry(t *testing.T) {
	oldCleanupErr := errors.New("close old egress")
	rollbackErr := errors.New("close replacement ingress")
	oldEgress := &testTCXLink{closeErrors: []error{oldCleanupErr, nil}}
	attachment := &SharedNetworkTCXAttachment{
		interfaceIndex: 1,
		egress:         sharedNetworkTCXLink{link: oldEgress, linkID: 1},
	}
	failedReplacementIngress := &testTCXLink{closeErrors: []error{rollbackErr, nil}}
	replacement := &SharedNetworkTCXAttachment{
		interfaceIndex: 2,
		ingress:        sharedNetworkTCXLink{link: failedReplacementIngress, linkID: 2},
		egress:         sharedNetworkTCXLink{link: &testTCXLink{}, linkID: 3},
	}

	changed, err := attachment.commitReplacementLocked(replacement)
	if changed || !errors.Is(err, oldCleanupErr) || !errors.Is(err, rollbackErr) {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if len(attachment.pendingCleanup) != 1 || attachment.pendingCleanup[0].link != failedReplacementIngress {
		t.Fatalf("failed rollback link was not retained: %+v", attachment.pendingCleanup)
	}

	retry := &SharedNetworkTCXAttachment{
		interfaceIndex: 2,
		ingress:        sharedNetworkTCXLink{link: &testTCXLink{}, linkID: 4},
		egress:         sharedNetworkTCXLink{link: &testTCXLink{}, linkID: 5},
	}
	changed, err = attachment.commitReplacementLocked(retry)
	if err != nil || !changed {
		t.Fatalf("retry changed=%v err=%v", changed, err)
	}
	if len(attachment.pendingCleanup) != 0 || failedReplacementIngress.closeCount != 2 {
		t.Fatalf("pending rollback cleanup was not retried: pending=%d closes=%d", len(attachment.pendingCleanup), failedReplacementIngress.closeCount)
	}
}

func TestTCXUnavailable(t *testing.T) {
	for _, err := range []error{
		link.ErrNotSupported,
		unix.ENOSYS,
		unix.EINVAL,
		unix.EOPNOTSUPP,
		linuxErrnoNotSupported,
		unix.EPERM,
		errors.Join(errors.New("attach TCX"), unix.EACCES),
	} {
		if !isTCXUnavailable(err) {
			t.Fatalf("expected TCX error to allow fallback: %v", err)
		}
	}
	if isTCXUnavailable(unix.ENOMEM) {
		t.Fatal("unexpectedly allowed TCX fallback after allocation failure")
	}
}

func TestTCXAttachmentStale(t *testing.T) {
	for _, err := range []error{unix.ENOENT, unix.ENODEV, unix.ENOLINK, unix.ESTALE} {
		if !isTCXAttachmentStale(err) {
			t.Fatalf("expected stale TCX attachment error: %v", err)
		}
	}
	if isTCXAttachmentStale(unix.EPERM) {
		t.Fatal("unexpectedly treated TCX permission failure as stale")
	}
}

// RepairTCX 会在每次 reconcile 时被调用（默认几秒一次）。如果某个 link 的 Close
// 永远失败，重试队列每轮都会再追加 —— 队列本身和它扣住的 fd 都会无限增长。
// 在只有 1-2GB 内存的路由设备上这是不能接受的，所以队列必须有硬上界。
func TestPendingCleanupIsBounded(t *testing.T) {
	closeErr := errors.New("close always fails")
	attachment := &SharedNetworkTCXAttachment{}

	// 模拟远多于上界的失败重试轮次。
	const rounds = maxPendingTCXCleanup * 5
	for i := 0; i < rounds; i++ {
		failing := &SharedNetworkTCXAttachment{
			ingress: sharedNetworkTCXLink{link: &testTCXLink{closeErrors: []error{closeErr}}},
			egress:  sharedNetworkTCXLink{link: &testTCXLink{closeErrors: []error{closeErr}}},
		}
		attachment.retainRemainingLinks(failing)
		if got := len(attachment.pendingCleanup); got > maxPendingTCXCleanup {
			t.Fatalf("第 %d 轮后队列长度 = %d，超过上界 %d", i+1, got, maxPendingTCXCleanup)
		}
	}
	if got := len(attachment.pendingCleanup); got != maxPendingTCXCleanup {
		t.Fatalf("持续失败后队列长度 = %d，期望稳定在上界 %d", got, maxPendingTCXCleanup)
	}
	// 被移交的一方必须被清空，否则同一个 link 会同时挂在两个对象上。
	survivor := &SharedNetworkTCXAttachment{
		ingress: sharedNetworkTCXLink{link: &testTCXLink{closeErrors: []error{closeErr}}},
	}
	attachment.retainRemainingLinks(survivor)
	if survivor.ingress.link != nil || survivor.egress.link != nil || survivor.pendingCleanup != nil {
		t.Fatal("移交后来源对象仍持有 link 引用")
	}
}
