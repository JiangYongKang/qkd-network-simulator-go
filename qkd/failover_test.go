package qkd

import (
	"bytes"
	"sync"
	"testing"
)

func logAttempts(t *testing.T, name string, seed int64, r FailoverResult) {
	t.Helper()
	t.Logf("[%s] seed=%d accepted=%v reason=%s path=%q attempts=%d",
		name, seed, r.Accepted, r.Reason, r.Path, len(r.Attempts))
	for _, a := range r.Attempts {
		t.Logf("[%s]   path=%s attempt=%d outcome=%s", name, a.Path, a.Attempt, a.Outcome)
	}
}

// TestFailoverRetrySuccess 短时故障路径：前两次不可用，重试后成功，
// 无需切换路径。
func TestFailoverRetrySuccess(t *testing.T) {
	cfg := DefaultRoundConfig()
	paths := []PathCandidate{
		{Name: "primary", Nodes: trustedPath(3, cfg.Channel), DownAttempts: 2},
	}
	const seed = 500
	r := RunWithFailover(paths, cfg, seed, 3)
	logAttempts(t, "failover-retry", seed, r)
	if !r.Accepted || r.Path != "primary" {
		t.Fatalf("重试后应在 primary 上成功，accepted=%v path=%q", r.Accepted, r.Path)
	}
	if len(r.Attempts) != 3 {
		t.Fatalf("应有 3 次尝试记录，得到 %d", len(r.Attempts))
	}
	for i := 0; i < 2; i++ {
		if r.Attempts[i].Reason != ReasonLinkUnavailable {
			t.Fatalf("前两次应为 link-unavailable，得到 %s", r.Attempts[i].Reason)
		}
	}
	if len(r.Key) != e2eKeyBytes {
		t.Fatalf("密钥长度应为 %d 字节，得到 %d", e2eKeyBytes, len(r.Key))
	}
}

// TestFailoverSwitchPath 主路径持续不可用，切换到备用路径后成功。
func TestFailoverSwitchPath(t *testing.T) {
	cfg := DefaultRoundConfig()
	paths := []PathCandidate{
		{Name: "primary", Nodes: trustedPath(3, cfg.Channel), DownAttempts: 5},
		{Name: "backup", Nodes: trustedPath(2, cfg.Channel)},
	}
	const seed = 501
	r := RunWithFailover(paths, cfg, seed, 2)
	logAttempts(t, "failover-switch", seed, r)
	if !r.Accepted || r.Path != "backup" {
		t.Fatalf("应切换到 backup 成功，accepted=%v path=%q", r.Accepted, r.Path)
	}
	// primary 重试 2 次后放弃，backup 第 1 次成功。
	if len(r.Attempts) != 3 {
		t.Fatalf("应有 3 次尝试记录，得到 %d", len(r.Attempts))
	}
}

// TestFailoverUntrustedPathSkipped 协议层面拒绝（节点不可信）不重试，
// 直接切换；成功密钥来自可信路径，不是降级结果。
func TestFailoverUntrustedPathSkipped(t *testing.T) {
	cfg := DefaultRoundConfig()
	bad := trustedPath(3, cfg.Channel)
	bad[1].Trusted = false
	paths := []PathCandidate{
		{Name: "untrusted", Nodes: bad},
		{Name: "trusted", Nodes: trustedPath(3, cfg.Channel)},
	}
	const seed = 502
	r := RunWithFailover(paths, cfg, seed, 3)
	logAttempts(t, "failover-untrusted", seed, r)
	if !r.Accepted || r.Path != "trusted" {
		t.Fatalf("应在 trusted 路径成功，accepted=%v path=%q", r.Accepted, r.Path)
	}
	// 不可信路径只尝试 1 次（不重试协议级失败）。
	if len(r.Attempts) != 2 || r.Attempts[0].Reason != ReasonUntrustedNode {
		t.Fatalf("不可信路径应只尝试一次并以 untrusted-node 结束: %+v", r.Attempts)
	}
	if len(r.Key) != e2eKeyBytes {
		t.Fatalf("成功密钥必须是完整端到端密钥，得到 %d 字节", len(r.Key))
	}
}

// TestFailoverAllPathsDown 所有路径都不可用时必须明确失败，
// 不携带任何密钥材料。
func TestFailoverAllPathsDown(t *testing.T) {
	cfg := DefaultRoundConfig()
	paths := []PathCandidate{
		{Name: "a", Nodes: trustedPath(2, cfg.Channel), DownAttempts: 10},
		{Name: "b", Nodes: trustedPath(2, cfg.Channel), FlakyProb: 1.0},
	}
	const seed = 503
	r := RunWithFailover(paths, cfg, seed, 3)
	logAttempts(t, "failover-all-down", seed, r)
	if r.Accepted || r.Key != nil || r.Path != "" {
		t.Fatalf("全部不可用时应明确失败且无密钥")
	}
	if r.Reason != ReasonNoUsablePath {
		t.Fatalf("期望 %s，得到 %s", ReasonNoUsablePath, r.Reason)
	}
}

// TestFailoverFlakyPath 时好时坏的路径：按概率不可用，重试后应成功；
// 判定依据来自确定性随机流，日志可见每次尝试的结论。
func TestFailoverFlakyPath(t *testing.T) {
	cfg := DefaultRoundConfig()
	paths := []PathCandidate{
		{Name: "flaky", Nodes: trustedPath(2, cfg.Channel), FlakyProb: 0.6},
	}
	const seed = 504
	r := RunWithFailover(paths, cfg, seed, 8)
	logAttempts(t, "failover-flaky", seed, r)
	if !r.Accepted {
		t.Fatalf("flaky 路径在 8 次重试内应成功，reason=%s", r.Reason)
	}
	if len(r.Attempts) < 1 {
		t.Fatalf("应至少有一次尝试记录")
	}
}

// TestFailoverReproducible 同一种子下整个尝试序列与最终密钥完全可复现。
func TestFailoverReproducible(t *testing.T) {
	cfg := DefaultRoundConfig()
	paths := []PathCandidate{
		{Name: "flaky", Nodes: trustedPath(2, cfg.Channel), FlakyProb: 0.5},
		{Name: "backup", Nodes: trustedPath(2, cfg.Channel), DownAttempts: 1},
	}
	const seed = 505
	r1 := RunWithFailover(paths, cfg, seed, 4)
	r2 := RunWithFailover(paths, cfg, seed, 4)
	logAttempts(t, "failover-repro", seed, r1)
	if r1.Accepted != r2.Accepted || r1.Path != r2.Path || !bytes.Equal(r1.Key, r2.Key) {
		t.Fatalf("同种子结果应一致")
	}
	if len(r1.Attempts) != len(r2.Attempts) {
		t.Fatalf("尝试次数应一致")
	}
	for i := range r1.Attempts {
		if r1.Attempts[i] != r2.Attempts[i] {
			t.Fatalf("第 %d 次尝试记录不一致", i)
		}
	}
}

// TestFailoverConcurrent 多会话并发执行切换流程，结果与串行一致，
// 在竞态检测器下无数据竞争。
func TestFailoverConcurrent(t *testing.T) {
	cfg := DefaultRoundConfig()
	const sessions = 6
	results := make([]FailoverResult, sessions)
	var wg sync.WaitGroup
	for i := 0; i < sessions; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			paths := []PathCandidate{
				{Name: "flaky", Nodes: trustedPath(2, cfg.Channel), FlakyProb: 0.4},
				{Name: "backup", Nodes: trustedPath(2, cfg.Channel)},
			}
			results[i] = RunWithFailover(paths, cfg, int64(600+i), 5)
		}(i)
	}
	wg.Wait()
	for i, r := range results {
		paths := []PathCandidate{
			{Name: "flaky", Nodes: trustedPath(2, cfg.Channel), FlakyProb: 0.4},
			{Name: "backup", Nodes: trustedPath(2, cfg.Channel)},
		}
		serial := RunWithFailover(paths, cfg, int64(600+i), 5)
		t.Logf("[failover-concurrent] session=%d seed=%d accepted=%v path=%q attempts=%d",
			i, 600+i, r.Accepted, r.Path, len(r.Attempts))
		if r.Accepted != serial.Accepted || !bytes.Equal(r.Key, serial.Key) {
			t.Fatalf("会话 %d 并发结果与串行不一致", i)
		}
	}
}
