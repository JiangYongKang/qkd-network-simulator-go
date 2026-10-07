package qkd

import (
	"bytes"
	"testing"
)

// TestHandshakeConsistent 正常路径：每跳两侧报告一致，产出端到端密钥，
// 且密钥与底层 RunRelay 在同种子下完全一致。
func TestHandshakeConsistent(t *testing.T) {
	cfg := DefaultRoundConfig()
	nodes := trustedPath(4, cfg.Channel)
	const seed = 20260
	res, reports := RunRelayHandshake(nodes, cfg, seed)
	t.Logf("[handshake-ok] seed=%d hops=%d reports=%d accepted=%v reason=%s",
		seed, len(nodes)-1, len(reports), res.Accepted, res.Reason)
	if !res.Accepted || len(res.Key) == 0 {
		t.Fatalf("一致路径应产出密钥，reason=%s detail=%s", res.Reason, res.Detail)
	}
	if err := VerifyHopReports(reports); err != nil {
		t.Fatalf("报告应通过独立复核: %v", err)
	}
	if len(reports) != 2*(len(nodes)-1) {
		t.Fatalf("每跳应有左右两份报告，期望 %d 得到 %d", 2*(len(nodes)-1), len(reports))
	}
	base := RunRelay(nodes, cfg, seed)
	if !bytes.Equal(res.Key, base.Key) {
		t.Fatalf("握手核验不应改变密钥内容")
	}
}

// TestHandshakeTamperedParams 任一跳任一侧的协商参数被改动，
// 核验必须失败，且失败结果不携带任何密钥材料。
func TestHandshakeTamperedParams(t *testing.T) {
	cfg := DefaultRoundConfig()
	nodes := trustedPath(3, cfg.Channel)
	const seed = 7777
	res, reports := RunRelayHandshake(nodes, cfg, seed)
	if !res.Accepted {
		t.Fatalf("基准运行应成功: %s", res.Reason)
	}
	// 篡改第 1 跳右侧报告的信道参数。
	reports[3].Params.LossDB += 0.5
	err := VerifyHopReports(reports)
	t.Logf("[handshake-tamper-params] seed=%d tampered=link1-right err=%v", seed, err)
	if err == nil {
		t.Fatalf("参数被篡改后核验必须失败")
	}
}

// TestHandshakeTamperedCredential 任一跳握手凭据对不上，核验必须失败。
func TestHandshakeTamperedCredential(t *testing.T) {
	cfg := DefaultRoundConfig()
	nodes := trustedPath(3, cfg.Channel)
	const seed = 8888
	_, reports := RunRelayHandshake(nodes, cfg, seed)
	reports[2].Credential[0] ^= 0xFF
	err := VerifyHopReports(reports)
	t.Logf("[handshake-tamper-cred] seed=%d tampered=link1-left-credential err=%v", seed, err)
	if err == nil {
		t.Fatalf("凭据被篡改后核验必须失败")
	}
}

// TestHandshakeMissingHop 报告缺失（某一跳只剩一侧）时核验必须失败。
func TestHandshakeMissingHop(t *testing.T) {
	cfg := DefaultRoundConfig()
	nodes := trustedPath(3, cfg.Channel)
	const seed = 9999
	_, reports := RunRelayHandshake(nodes, cfg, seed)
	broken := append(reports[:2], reports[3:]...) // 删掉第 1 跳右侧报告
	err := VerifyHopReports(broken)
	t.Logf("[handshake-missing] seed=%d reports=%d err=%v", seed, len(broken), err)
	if err == nil {
		t.Fatalf("报告缺失时核验必须失败")
	}
}

// TestHandshakeFailureCarriesNoKey 核验失败路径：构造一个核验必失败的
// 场景（不可信节点），确认结果不含任何密钥材料，且 Reason 可区分。
func TestHandshakeFailureCarriesNoKey(t *testing.T) {
	cfg := DefaultRoundConfig()
	nodes := trustedPath(3, cfg.Channel)
	nodes[1].Trusted = false
	const seed = 11111
	res, reports := RunRelayHandshake(nodes, cfg, seed)
	t.Logf("[handshake-untrusted] seed=%d accepted=%v reason=%s keyLen=%d reports=%d",
		seed, res.Accepted, res.Reason, len(res.Key), len(reports))
	if res.Accepted || res.Key != nil {
		t.Fatalf("失败轮次不得携带密钥材料")
	}
	if res.Reason != ReasonUntrustedNode {
		t.Fatalf("期望 %s，得到 %s", ReasonUntrustedNode, res.Reason)
	}
	if len(reports) != 0 {
		t.Fatalf("失败轮次不应产生握手报告")
	}
}

// TestHandshakeReproducible 同一种子下报告与密钥完全可复现。
func TestHandshakeReproducible(t *testing.T) {
	cfg := DefaultRoundConfig()
	nodes := trustedPath(3, cfg.Channel)
	const seed = 12121
	r1, rep1 := RunRelayHandshake(nodes, cfg, seed)
	r2, rep2 := RunRelayHandshake(nodes, cfg, seed)
	t.Logf("[handshake-repro] seed=%d accepted=%v reports=%d", seed, r1.Accepted, len(rep1))
	if !bytes.Equal(r1.Key, r2.Key) || !reportsEqual(rep1, rep2) {
		t.Fatalf("同种子下密钥与握手报告应完全一致")
	}
}
