package qkd

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
)

// trustedPath 构造一条全部可信、参数一致的路径。
func trustedPath(n int, ch ChannelParams) []Node {
	nodes := make([]Node, n)
	for i := range nodes {
		nodes[i] = Node{
			ID:              fmt.Sprintf("node-%d", i),
			Trusted:         true,
			ExpectedChannel: ch,
		}
	}
	return nodes
}

func logRelay(t *testing.T, name string, seed int64, nodes []Node, cfg RoundConfig, r RelayResult) {
	t.Helper()
	t.Logf("[%s] seed=%d hops=%d pulses=%d accepted=%v reason=%s detail=%q",
		name, seed, len(nodes)-1, cfg.NumPulses, r.Accepted, r.Reason, r.Detail)
	for _, lr := range r.Links {
		t.Logf("[%s] link %s->%s accepted=%v reason=%s qber=%.4f sifted=%d finalBits=%d",
			name, lr.From, lr.To, lr.Round.Accepted, lr.Round.Reason,
			lr.Round.QBER, lr.Round.SiftedBits, lr.Round.FinalKeyBits)
	}
}

// TestRelaySuccess 可信路径应产出端到端密钥，且密钥不同于任何链路密钥。
func TestRelaySuccess(t *testing.T) {
	cfg := DefaultRoundConfig()
	nodes := trustedPath(4, cfg.Channel)
	const seed = 2026
	r := RunRelay(nodes, cfg, seed)
	logRelay(t, "relay-ok", seed, nodes, cfg, r)
	if !r.Accepted {
		t.Fatalf("可信路径应成功，reason=%s detail=%s", r.Reason, r.Detail)
	}
	if len(r.Key) != e2eKeyBytes {
		t.Fatalf("端到端密钥长度应为 %d 字节，得到 %d", e2eKeyBytes, len(r.Key))
	}
	if len(r.Links) != len(nodes)-1 {
		t.Fatalf("应有 %d 条链路结果，得到 %d", len(nodes)-1, len(r.Links))
	}
	// 中间节点只持有链路密钥；端到端密钥不得等于任何链路密钥。
	for _, lr := range r.Links {
		if bytes.Equal(r.Key, lr.Round.Key) {
			t.Fatalf("端到端密钥不得与链路 %s->%s 的密钥相同", lr.From, lr.To)
		}
	}
}

// TestRelayReproducible 相同种子下中继结果可复现。
func TestRelayReproducible(t *testing.T) {
	cfg := DefaultRoundConfig()
	nodes := trustedPath(3, cfg.Channel)
	const seed = 88
	r1 := RunRelay(nodes, cfg, seed)
	r2 := RunRelay(nodes, cfg, seed)
	logRelay(t, "relay-repro", seed, nodes, cfg, r1)
	if !r1.Accepted || !r2.Accepted {
		t.Fatalf("两次运行都应成功：%s / %s", r1.Reason, r2.Reason)
	}
	if !bytes.Equal(r1.Key, r2.Key) {
		t.Fatalf("相同种子端到端密钥应一致")
	}
	for i := range r1.Links {
		if !bytes.Equal(r1.Links[i].Round.Key, r2.Links[i].Round.Key) {
			t.Fatalf("链路 %d 密钥在相同种子下应一致", i)
		}
	}
}

// TestRelayUntrustedNodeFails 任一节点不可信必须整体失败。
func TestRelayUntrustedNodeFails(t *testing.T) {
	cfg := DefaultRoundConfig()
	nodes := trustedPath(3, cfg.Channel)
	nodes[1].Trusted = false
	const seed = 5
	r := RunRelay(nodes, cfg, seed)
	logRelay(t, "relay-untrusted", seed, nodes, cfg, r)
	if r.Accepted || r.Key != nil {
		t.Fatalf("不可信节点存在时不得产出密钥")
	}
	if r.Reason != ReasonUntrustedNode {
		t.Fatalf("期望 %s，得到 %s", ReasonUntrustedNode, r.Reason)
	}
}

// TestRelayParamMismatchFails 节点参数不一致必须整体失败。
func TestRelayParamMismatchFails(t *testing.T) {
	cfg := DefaultRoundConfig()
	nodes := trustedPath(3, cfg.Channel)
	nodes[2].ExpectedChannel.LossDB += 1 // 与链路参数不一致
	const seed = 6
	r := RunRelay(nodes, cfg, seed)
	logRelay(t, "relay-mismatch", seed, nodes, cfg, r)
	if r.Accepted || r.Key != nil {
		t.Fatalf("参数不一致时不得产出密钥")
	}
	if r.Reason != ReasonParamMismatch {
		t.Fatalf("期望 %s，得到 %s", ReasonParamMismatch, r.Reason)
	}
}

// TestRelayEavesdropFails 任一跳被窃听时整体失败且原因可区分。
func TestRelayEavesdropFails(t *testing.T) {
	cfg := DefaultRoundConfig()
	cfg.Eve = EveConfig{Enabled: true, InterceptProb: 1.0}
	nodes := trustedPath(3, cfg.Channel)
	const seed = 9
	r := RunRelay(nodes, cfg, seed)
	logRelay(t, "relay-eve", seed, nodes, cfg, r)
	if r.Accepted || r.Key != nil {
		t.Fatalf("窃听下不得产出密钥")
	}
	if r.Reason != ReasonEavesdropSuspected {
		t.Fatalf("期望 %s，得到 %s", ReasonEavesdropSuspected, r.Reason)
	}
}

// TestRelayInvalidInput 非法输入必须明确失败。
func TestRelayInvalidInput(t *testing.T) {
	cfg := DefaultRoundConfig()
	if r := RunRelay(nil, cfg, 1); r.Reason != ReasonInvalidParams || r.Accepted {
		t.Fatalf("空路径期望 %s，得到 %s", ReasonInvalidParams, r.Reason)
	}
	single := trustedPath(1, cfg.Channel)
	if r := RunRelay(single, cfg, 1); r.Reason != ReasonInvalidParams || r.Accepted {
		t.Fatalf("单节点路径期望 %s，得到 %s", ReasonInvalidParams, r.Reason)
	}
	badCfg := cfg
	badCfg.NumPulses = 0
	if r := RunRelay(trustedPath(2, cfg.Channel), badCfg, 1); r.Reason != ReasonInvalidParams || r.Accepted {
		t.Fatalf("非法配置期望 %s，得到 %s", ReasonInvalidParams, r.Reason)
	}
}

// TestConcurrentRoundsNoRace 多条轮次共享随机源并发推进，
// 在竞态检测器下不得出现数据竞争，且结果与串行一致。
func TestConcurrentRoundsNoRace(t *testing.T) {
	cfg := DefaultRoundConfig()
	root := NewLockedSource(4242)
	const workers = 8
	results := make([]RoundResult, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = RunBB84Round(cfg, root.Derive(fmt.Sprintf("worker-%d", i)))
		}(i)
	}
	wg.Wait()
	for i, r := range results {
		serial := RunBB84Round(cfg, root.Derive(fmt.Sprintf("worker-%d", i)))
		t.Logf("[concurrent] worker=%d accepted=%v reason=%s qber=%.4f finalBits=%d",
			i, r.Accepted, r.Reason, r.QBER, r.FinalKeyBits)
		if r.Accepted != serial.Accepted || !bytes.Equal(r.Key, serial.Key) {
			t.Fatalf("worker %d 并发结果与串行不一致", i)
		}
	}
}

// TestConcurrentRelays 多条中继路径并行推进，结果与串行一致。
func TestConcurrentRelays(t *testing.T) {
	cfg := DefaultRoundConfig()
	const paths = 4
	results := make([]RelayResult, paths)
	var wg sync.WaitGroup
	for i := 0; i < paths; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = RunRelay(trustedPath(3, cfg.Channel), cfg, int64(1000+i))
		}(i)
	}
	wg.Wait()
	for i, r := range results {
		serial := RunRelay(trustedPath(3, cfg.Channel), cfg, int64(1000+i))
		t.Logf("[concurrent-relay] path=%d accepted=%v reason=%s", i, r.Accepted, r.Reason)
		if !r.Accepted {
			t.Fatalf("路径 %d 应成功，reason=%s", i, r.Reason)
		}
		if !bytes.Equal(r.Key, serial.Key) {
			t.Fatalf("路径 %d 并发与串行密钥不一致", i)
		}
	}
	// 不同路径的端到端密钥应互不相同。
	for i := 0; i < paths; i++ {
		for j := i + 1; j < paths; j++ {
			if bytes.Equal(results[i].Key, results[j].Key) {
				t.Fatalf("路径 %d 与 %d 的端到端密钥不应相同", i, j)
			}
		}
	}
}
