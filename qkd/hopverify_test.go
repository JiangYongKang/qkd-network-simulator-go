package qkd

import (
	"testing"
)

func logHopChecks(t *testing.T, name string, checks []HopCheck) {
	t.Helper()
	for _, c := range checks {
		t.Logf("[%s] 跳 %s->%s ok=%v 判定依据=%s", name, c.From, c.To, c.OK, c.Detail)
	}
}

// TestHopVerifyAllPass 正常路径每一跳核验都应通过。
func TestHopVerifyAllPass(t *testing.T) {
	cfg := DefaultRoundConfig()
	nodes := trustedPath(4, cfg.Channel)
	const seed = 31415
	r := RunRelay(nodes, cfg, seed)
	if !r.Accepted {
		t.Fatalf("可信路径中继应成功，reason=%s", r.Reason)
	}
	checks := VerifyRelayHops(nodes, cfg, r)
	t.Logf("[hopverify] 场景=全通过 seed=%d 跳数=%d", seed, len(checks))
	logHopChecks(t, "hopverify-ok", checks)
	if !hopsAllOK(checks) {
		t.Fatalf("正常路径所有跳应核验通过：%s", firstFailedHop(checks))
	}
	// RunRelayVerified 应正常产出密钥。
	rv := RunRelayVerified(nodes, cfg, seed)
	if !rv.Accepted || len(rv.Key) == 0 {
		t.Fatalf("核验通过的路径应产出密钥，reason=%s", rv.Reason)
	}
}

// TestHopVerifyTamperedLinkKey 篡改任一跳的链路密钥后，
// 该跳握手凭据复算必须失败。
func TestHopVerifyTamperedLinkKey(t *testing.T) {
	cfg := DefaultRoundConfig()
	nodes := trustedPath(3, cfg.Channel)
	const seed = 2718
	r := RunRelay(nodes, cfg, seed)
	if !r.Accepted {
		t.Fatalf("中继应成功，reason=%s", r.Reason)
	}
	// 篡改第 1 跳的链路密钥（模拟协商结果对不上）。
	r.Links[1].Round.Key[0] ^= 0xFF
	checks := VerifyRelayHops(nodes, cfg, r)
	t.Logf("[hopverify] 场景=篡改链路密钥 seed=%d 篡改跳=%d", seed, 1)
	logHopChecks(t, "hopverify-tamper-key", checks)
	if checks[1].OK {
		t.Fatalf("被篡改的跳不得核验通过")
	}
	if !checks[0].OK {
		t.Fatalf("未篡改的跳不应受牵连：%s", checks[0].Detail)
	}
}

// TestHopVerifyTamperedHandshake 篡改握手消息后，
// 每一跳的凭据复算都必须失败。
func TestHopVerifyTamperedHandshake(t *testing.T) {
	cfg := DefaultRoundConfig()
	nodes := trustedPath(3, cfg.Channel)
	const seed = 161
	r := RunRelay(nodes, cfg, seed)
	if !r.Accepted {
		t.Fatalf("中继应成功，reason=%s", r.Reason)
	}
	r.HandshakeFwd[0] ^= 0x01
	checks := VerifyRelayHops(nodes, cfg, r)
	t.Logf("[hopverify] 场景=篡改握手消息 seed=%d", seed)
	logHopChecks(t, "hopverify-tamper-hs", checks)
	if hopsAllOK(checks) {
		t.Fatalf("握手消息被篡改后不得全部核验通过")
	}
}

// TestHopVerifyParamMismatch 节点期望参数与会话参数不一致时，
// 对应跳核验失败，且 RunRelay 整体直接失败、不产出密钥。
func TestHopVerifyParamMismatch(t *testing.T) {
	cfg := DefaultRoundConfig()
	nodes := trustedPath(3, cfg.Channel)
	nodes[1].ExpectedChannel.LossDB += 2 // 中间节点认可的参数与链路不一致
	const seed = 77
	r := RunRelayVerified(nodes, cfg, seed)
	t.Logf("[hopverify] 场景=参数不一致 seed=%d accepted=%v reason=%s detail=%q",
		seed, r.Accepted, r.Reason, r.Detail)
	if r.Accepted || r.Key != nil {
		t.Fatalf("参数不一致时不得产出密钥")
	}
	if r.Reason != ReasonParamMismatch {
		t.Fatalf("期望 %s，得到 %s", ReasonParamMismatch, r.Reason)
	}
}

// TestHopVerifyFailedLinkNoKey 链路核验失败（任一跳被拒）时，
// 端到端流程必须失败且没有任何密钥材料流向后续环节。
func TestHopVerifyFailedLinkNoKey(t *testing.T) {
	cfg := DefaultRoundConfig()
	cfg.Eve = EveConfig{Enabled: true, InterceptProb: 1.0} // 全程窃听，链路必被拒
	nodes := trustedPath(3, cfg.Channel)
	const seed = 99
	r := RunRelayVerified(nodes, cfg, seed)
	t.Logf("[hopverify] 场景=链路被拒 seed=%d accepted=%v reason=%s detail=%q key=%v",
		seed, r.Accepted, r.Reason, r.Detail, r.Key)
	if r.Accepted {
		t.Fatalf("链路被拒时端到端流程不得成功")
	}
	if r.Key != nil {
		t.Fatalf("失败轮次不得有任何密钥材料流出")
	}
	// 逐跳核验同样必须能指出失败跳。
	checks := VerifyRelayHops(nodes, cfg, r)
	logHopChecks(t, "hopverify-rejected-link", checks)
	if hopsAllOK(checks) {
		t.Fatalf("存在被拒链路时不得全部核验通过")
	}
}
