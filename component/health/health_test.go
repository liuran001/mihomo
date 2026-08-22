package health

import (
	"fmt"
	"testing"
	"time"
)

func reset() { store.Range(func(k, _ any) bool { store.Delete(k); return true }) }

func TestPenaltyGrowsAndCaps(t *testing.T) {
	reset()
	if got := Penalty("A"); got != 0 {
		t.Fatalf("未记账时应为 0，得到 %d", got)
	}
	RecordStall("A")
	if got := Penalty("A"); got != penaltyPerEvent {
		t.Errorf("1 次事件应为 %d，得到 %d", penaltyPerEvent, got)
	}
	for i := 0; i < 3; i++ {
		RecordStall("A")
	}
	if got := Penalty("A"); got != 4*penaltyPerEvent {
		t.Errorf("4 次事件应为 %d，得到 %d", 4*penaltyPerEvent, got)
	}
	for i := 0; i < 40; i++ {
		RecordStall("A")
	}
	if got := Penalty("A"); got != penaltyCap {
		t.Errorf("大量事件应封顶在 %d，得到 %d", penaltyCap, got)
	}
	if n := Incidents("A"); n > maxEvents {
		t.Errorf("事件数应受 maxEvents=%d 限制，得到 %d", maxEvents, n)
	}
}

func TestPenaltyExpires(t *testing.T) {
	reset()
	r := recordFor("B")
	r.mu.Lock()
	r.events = append(r.events, time.Now().Add(-window-time.Minute)) // 窗口外
	r.events = append(r.events, time.Now())                          // 窗口内
	r.mu.Unlock()
	if got, want := Penalty("B"), uint16(penaltyPerEvent); got != want {
		t.Errorf("过期事件不应计入：期望 %d，得到 %d", want, got)
	}
	if n := Incidents("B"); n != 1 {
		t.Errorf("窗口内事件应为 1，得到 %d", n)
	}
}

func TestEmptyNameIgnored(t *testing.T) {
	reset()
	RecordStall("")
	if got := Penalty(""); got != 0 {
		t.Errorf("空名应忽略，得到 %d", got)
	}
}

func TestProxyKeySeparatesProviders(t *testing.T) {
	reset()
	first := ProxyKey("node", "provider-a")
	second := ProxyKey("node", "provider-b")
	if first == second {
		t.Fatal("provider-aware health keys collided")
	}
	RecordStall(first)
	if got := Penalty(second); got != 0 {
		t.Fatalf("stall for another provider leaked into this key: %d", got)
	}
	if got := Penalty(first); got != penaltyPerEvent {
		t.Fatalf("provider-specific stall penalty = %d, want %d", got, penaltyPerEvent)
	}
}

// RecordStall 是无条件调用的，而 Penalty 只在开启 penalize-unstable 时才会被调到。
// 清扫如果只挂在 Penalty 上，没开该选项的配置就会让 store 只增不减 —— 在只有
// 1-2GB 内存的路由设备上这是不能接受的。这里证明写入路径自己能驱动回收。
func TestStoreReclaimsWithoutPenaltyCalls(t *testing.T) {
	reset()

	// 先放入一批"陈旧"记录：事件在窗口外，且 lastUsed 也早已过期。
	const stale = 50
	for i := 0; i < stale; i++ {
		key := ProxyKey(fmt.Sprintf("gone-node-%d", i), "provider")
		r := recordFor(key)
		r.mu.Lock()
		r.events = append(r.events, time.Now().Add(-2*window))
		r.lastUsed = time.Now().Add(-2 * idleTTL)
		r.mu.Unlock()
	}
	if got := countRecords(); got < stale {
		t.Fatalf("预置记录数 = %d，期望至少 %d", got, stale)
	}

	// 只调 RecordStall，完全不碰 Penalty/Incidents，足以触发清扫。
	for i := 0; i < sweepEvery+1; i++ {
		RecordStall(ProxyKey("live-node", "provider"))
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if countRecords() <= 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("仅有写入而无 Penalty 调用时陈旧记录未被回收，仍剩 %d 条", countRecords())
}

func countRecords() int {
	n := 0
	store.Range(func(any, any) bool { n++; return true })
	return n
}
