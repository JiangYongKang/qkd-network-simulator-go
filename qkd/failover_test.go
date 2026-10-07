package qkd

import (
	"bytes"
	"sync"
	"testing"
)

func logAttempts(t *testing.T, name string, fr FailoverResult) {
	t.Helper()
	t.Logf("[%s] accepted=%v reason=%s pathUsed=%d 尝试次数=%d",
		name, fr.Accepted, fr.Reason, fr.PathUsed, len(fr.Attempts))
	for _, att := range fr.Attempts {
		t.Logf("[%s] 路径=%d 尝试=%d accepted=%v reason=%s detail=%q",
			name, att.Path, att.Attempt, att.Accepted, att.Reason, att.Detail)
	}
}

// TestFailoverFirstPathHealthy 首选路径可用时应一次成功。
func TestFailoverFirstPathHealthy(t *testing.T) {
	cfg := DefaultRoundConfig()
	paths := [][]Node{trustedPath(3, cfg.Channel), trustedPath(3, cfg.Channel)}
	const seed = 5001
	fr := RunRelayWithFailover(paths, cfg, seed, 3, nil)
	t.Logf("[failover] 场景=首选路径可用 seed=%d", seed)
	logAttempts(t, "failover-direct", fr)
	if !fr.Accepted || fr.PathUsed != 0 || len(fr.Key) == 0 {
		t.Fatalf("首选路径应一次成功，accepted=%v pathUsed=%d", fr.Accepted, fr.PathUsed)
	}
	if len(fr.Attempts) != 1 {
		t.Fatalf("应只尝试 1 次，得到 %d", len(fr.Attempts))
	}
}

// TestFailoverRetryFlakyLink 链路时好时坏：首次不可用，重试后成功。
func TestFailoverRetryFlakyLink(t *testing.T) {
	cfg := DefaultRoundConfig()
	paths := [][]Node{trustedPath(3, cfg.Channel)}
	const seed = 5002
	// 路径 0 第 0 次尝试不可用，第 1 次恢复。
	flaky := func(path, attempt int) bool { return attempt >= 1 }
	fr := RunRelayWithFailover(paths, cfg, seed, 3, flaky)
	t.Logf("[failover] 场景=时好时坏重试 seed=%d 规则=第0次不可用", seed)
	logAttempts(t, "failover-retry", fr)
	if !fr.Accepted || fr.PathUsed != 0 {
		t.Fatalf("重试后应成功，pathUsed=%d", fr.PathUsed)
	}
	if len(fr.Attempts) != 2 || fr.Attempts[0].Reason != ReasonLinkUnavailable {
		t.Fatalf("首次尝试应记录为 %s", ReasonLinkUnavailable)
	}
	if len(fr.Key) == 0 {
		t.Fatalf("重试成功应产出密钥")
	}
}

// TestFailoverSwitchPath 首选路径持续不可用时切换到备用路径。
func TestFailoverSwitchPath(t *testing.T) {
	cfg := DefaultRoundConfig()
	paths := [][]Node{trustedPath(3, cfg.Channel), trustedPath(3, cfg.Channel)}
	const seed = 5003
	// 路径 0 始终不可用，路径 1 可用。
	down0 := func(path, attempt int) bool { return path != 0 }
	fr := RunRelayWithFailover(paths, cfg, seed, 2, down0)
	t.Logf("[failover] 场景=切换备用路径 seed=%d 规则=路径0持续不可用", seed)
	logAttempts(t, "failover-switch", fr)
	if !fr.Accepted || fr.PathUsed != 1 {
		t.Fatalf("应切换到路径 1 成功，pathUsed=%d", fr.PathUsed)
	}
	// 前两次尝试应都是路径 0 的 link-unavailable。
	for i := 0; i < 2; i++ {
		if fr.Attempts[i].Path != 0 || fr.Attempts[i].Reason != ReasonLinkUnavailable {
			t.Fatalf("路径 0 的尝试应记录为不可用：%+v", fr.Attempts[i])
		}
	}
}

// TestFailoverAllPathsDown 所有路径都不可用时必须明确失败，
// 不得产出任何密钥。
func TestFailoverAllPathsDown(t *testing.T) {
	cfg := DefaultRoundConfig()
	paths := [][]Node{trustedPath(3, cfg.Channel), trustedPath(3, cfg.Channel)}
	const seed = 5004
	allDown := func(path, attempt int) bool { return false }
	fr := RunRelayWithFailover(paths, cfg, seed, 2, allDown)
	t.Logf("[failover] 场景=全部路径不可用 seed=%d", seed)
	logAttempts(t, "failover-alldown", fr)
	if fr.Accepted || fr.Key != nil || fr.PathUsed != -1 {
		t.Fatalf("所有路径不可用时不得产出密钥")
	}
	if fr.Reason != ReasonNoUsablePath {
		t.Fatalf("期望 %s，得到 %s", ReasonNoUsablePath, fr.Reason)
	}
	if len(fr.Attempts) != 4 {
		t.Fatalf("应记录 4 次失败尝试，得到 %d", len(fr.Attempts))
	}
}

// TestFailoverUntrustedPath 路径上存在不可信节点时该路径的尝试失败；
// 所有路径都不可信时整体明确失败，不产出降级密钥。
func TestFailoverUntrustedPath(t *testing.T) {
	cfg := DefaultRoundConfig()
	bad := trustedPath(3, cfg.Channel)
	bad[1].Trusted = false
	good := trustedPath(3, cfg.Channel)
	const seed = 5005

	// 不可信路径在前：应切换到可信路径成功。
	fr := RunRelayWithFailover([][]Node{bad, good}, cfg, seed, 1, nil)
	t.Logf("[failover] 场景=不可信路径在前 seed=%d", seed)
	logAttempts(t, "failover-untrusted-first", fr)
	if !fr.Accepted || fr.PathUsed != 1 {
		t.Fatalf("应切换到可信路径成功，pathUsed=%d", fr.PathUsed)
	}
	if fr.Attempts[0].Reason != ReasonUntrustedNode {
		t.Fatalf("不可信路径的尝试应记录 %s，得到 %s", ReasonUntrustedNode, fr.Attempts[0].Reason)
	}

	// 所有路径都不可信：整体失败、无密钥。
	fr2 := RunRelayWithFailover([][]Node{bad, bad}, cfg, seed, 2, nil)
	t.Logf("[failover] 场景=全部路径不可信 seed=%d", seed)
	logAttempts(t, "failover-all-untrusted", fr2)
	if fr2.Accepted || fr2.Key != nil {
		t.Fatalf("所有路径不可信时不得产出密钥（不允许降级成功）")
	}
	if fr2.Reason != ReasonNoUsablePath {
		t.Fatalf("期望 %s，得到 %s", ReasonNoUsablePath, fr2.Reason)
	}
}

// TestFailoverReproducible 同一种子的切换/重试序列与产出密钥完全可复现。
func TestFailoverReproducible(t *testing.T) {
	cfg := DefaultRoundConfig()
	paths := [][]Node{trustedPath(3, cfg.Channel), trustedPath(3, cfg.Channel)}
	const seed = 5006
	flaky := func(path, attempt int) bool { return !(path == 0 && attempt == 0) }
	fr1 := RunRelayWithFailover(paths, cfg, seed, 3, flaky)
	fr2 := RunRelayWithFailover(paths, cfg, seed, 3, flaky)
	t.Logf("[failover] 场景=可复现 seed=%d", seed)
	logAttempts(t, "failover-repro-1", fr1)
	if fr1.Accepted != fr2.Accepted || fr1.PathUsed != fr2.PathUsed ||
		!bytes.Equal(fr1.Key, fr2.Key) || len(fr1.Attempts) != len(fr2.Attempts) {
		t.Fatalf("同种子两次运行结论应一致")
	}
	for i := range fr1.Attempts {
		a, b := fr1.Attempts[i], fr2.Attempts[i]
		if a.Accepted != b.Accepted || a.Reason != b.Reason {
			t.Fatalf("第 %d 次尝试记录在同种子下应一致", i)
		}
	}
}

// TestFailoverInvalidInput 非法输入必须明确失败。
func TestFailoverInvalidInput(t *testing.T) {
	cfg := DefaultRoundConfig()
	if fr := RunRelayWithFailover(nil, cfg, 1, 1, nil); fr.Reason != ReasonInvalidParams || fr.Accepted {
		t.Fatalf("空路径列表期望 %s，得到 %s", ReasonInvalidParams, fr.Reason)
	}
	paths := [][]Node{trustedPath(2, cfg.Channel)}
	if fr := RunRelayWithFailover(paths, cfg, 1, 0, nil); fr.Reason != ReasonInvalidParams || fr.Accepted {
		t.Fatalf("重试次数非正期望 %s，得到 %s", ReasonInvalidParams, fr.Reason)
	}
}

// TestFailoverConcurrent 多个会话并发执行切换/重试，
// 竞态检测下无数据竞争且结果与串行一致。
func TestFailoverConcurrent(t *testing.T) {
	cfg := DefaultRoundConfig()
	const sessions = 4
	flaky := func(path, attempt int) bool { return attempt >= 1 }
	results := make([]FailoverResult, sessions)
	var wg sync.WaitGroup
	for i := 0; i < sessions; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			paths := [][]Node{trustedPath(3, cfg.Channel), trustedPath(3, cfg.Channel)}
			results[i] = RunRelayWithFailover(paths, cfg, int64(6000+i), 3, flaky)
		}(i)
	}
	wg.Wait()
	for i, fr := range results {
		paths := [][]Node{trustedPath(3, cfg.Channel), trustedPath(3, cfg.Channel)}
		serial := RunRelayWithFailover(paths, cfg, int64(6000+i), 3, flaky)
		t.Logf("[failover] 场景=并发会话 session=%d accepted=%v pathUsed=%d",
			i, fr.Accepted, fr.PathUsed)
		if !fr.Accepted || !bytes.Equal(fr.Key, serial.Key) || fr.PathUsed != serial.PathUsed {
			t.Fatalf("会话 %d 并发结果与串行不一致", i)
		}
	}
}
