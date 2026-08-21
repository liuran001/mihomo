package health

import (
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
