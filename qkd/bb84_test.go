package qkd

import (
	"bytes"
	"testing"
)

// logResult 按要求在测试日志中打印随机种子、关键参数与判定依据。
func logRound(t *testing.T, name string, seed int64, cfg RoundConfig, r RoundResult) {
	t.Helper()
	t.Logf("[%s] seed=%d pulses=%d loss=%.1fdB detEff=%.2f dark=%.1e depol=%.3f eve=%v(%.2f) thr=%.2f",
		name, seed, cfg.NumPulses, cfg.Channel.LossDB, cfg.Channel.DetectorEfficiency,
		cfg.Channel.DarkCountProb, cfg.Channel.DepolarizationProb,
		cfg.Eve.Enabled, cfg.Eve.InterceptProb, cfg.QBERThreshold)
	t.Logf("[%s] accepted=%v reason=%s attribution=%s sifted=%d sample=%d errs=%d qber=%.4f baseline=%.4f trueNoise=%d trueEve=%d corrected=%d leaked=%d finalBits=%d",
		name, r.Accepted, r.Reason, r.Attribution, r.SiftedBits, r.SampleBits, r.SampleErrors,
		r.QBER, r.NaturalBaseline, r.TrueNoiseErrors, r.TrueEveErrors,
		r.CorrectedBits, r.LeakedBits, r.FinalKeyBits)
}

// TestReproducibility 相同随机种子下两轮结果必须完全一致。
func TestReproducibility(t *testing.T) {
	cfg := DefaultRoundConfig()
	const seed = 42
	r1 := RunBB84Round(cfg, NewLockedSource(seed))
	r2 := RunBB84Round(cfg, NewLockedSource(seed))
	logRound(t, "repro-1", seed, cfg, r1)
	logRound(t, "repro-2", seed, cfg, r2)
	if !r1.Accepted {
		t.Fatalf("默认参数下轮次应被接受，实际 reason=%s", r1.Reason)
	}
	if !bytes.Equal(r1.Key, r2.Key) {
		t.Fatalf("相同种子应产出相同密钥\n k1=%x\n k2=%x", r1.Key, r2.Key)
	}
	if r1.SiftedBits != r2.SiftedBits || r1.QBER != r2.QBER || r1.FinalKeyBits != r2.FinalKeyBits {
		t.Fatalf("相同种子统计量应一致：%+v vs %+v", r1, r2)
	}
	// 不同种子应产出不同密钥。
	r3 := RunBB84Round(cfg, NewLockedSource(seed+1))
	if bytes.Equal(r1.Key, r3.Key) {
		t.Fatalf("不同种子不应产出相同密钥")
	}
}

// TestKeyLengthNeverNegativeOrGrowing 密钥长度不得为负或凭空增长。
func TestKeyLengthNeverNegativeOrGrowing(t *testing.T) {
	cfg := DefaultRoundConfig()
	const seed = 7
	r := RunBB84Round(cfg, NewLockedSource(seed))
	logRound(t, "length", seed, cfg, r)
	if !r.Accepted {
		t.Fatalf("轮次应被接受，reason=%s", r.Reason)
	}
	if r.CorrectedBits > r.SiftedBits {
		t.Fatalf("纠错后比特数 %d 不得多于筛选比特数 %d", r.CorrectedBits, r.SiftedBits)
	}
	if r.FinalKeyBits <= 0 {
		t.Fatalf("接受轮次的最终密钥长度必须为正，得到 %d", r.FinalKeyBits)
	}
	if r.FinalKeyBits > r.CorrectedBits {
		t.Fatalf("隐私放大后比特数 %d 不得多于纠错后比特数 %d", r.FinalKeyBits, r.CorrectedBits)
	}
	if got := len(r.Key) * 8; got < r.FinalKeyBits {
		t.Fatalf("密钥字节数 %d 比特不足以承载声明的 %d 比特", got, r.FinalKeyBits)
	}
}

// TestNaturalNoiseAccepted 纯自然噪声在阈值内应被接受并归因为自然噪声。
func TestNaturalNoiseAccepted(t *testing.T) {
	cfg := DefaultRoundConfig()
	cfg.Channel.DepolarizationProb = 0.02 // 自然噪声，预期 QBER ~1%
	const seed = 1234
	r := RunBB84Round(cfg, NewLockedSource(seed))
	logRound(t, "noise", seed, cfg, r)
	if !r.Accepted {
		t.Fatalf("纯自然噪声应被接受，reason=%s qber=%.4f", r.Reason, r.QBER)
	}
	if r.Attribution != AttributionNaturalNoise && r.Attribution != AttributionNone {
		t.Fatalf("纯自然噪声不应被归因为窃听，得到 %s", r.Attribution)
	}
	if r.TrueEveErrors != 0 {
		t.Fatalf("无窃听时不应有窃听误码，得到 %d", r.TrueEveErrors)
	}
}

// TestEavesdropDetected 拦截-重发窃听必须被识别并与自然噪声区分。
func TestEavesdropDetected(t *testing.T) {
	cfg := DefaultRoundConfig()
	cfg.Eve = EveConfig{Enabled: true, InterceptProb: 1.0}
	const seed = 99
	r := RunBB84Round(cfg, NewLockedSource(seed))
	logRound(t, "eve", seed, cfg, r)
	if r.Accepted {
		t.Fatalf("全量拦截-重发必须被拒绝")
	}
	if r.Reason != ReasonEavesdropSuspected {
		t.Fatalf("窃听轮次拒绝原因应为 %s，得到 %s", ReasonEavesdropSuspected, r.Reason)
	}
	if r.Attribution != AttributionEavesdrop {
		t.Fatalf("窃听轮次归因应为 %s，得到 %s", AttributionEavesdrop, r.Attribution)
	}
	if r.Key != nil {
		t.Fatalf("被拒轮次不得携带密钥材料，得到 %x", r.Key)
	}
	if r.TrueEveErrors == 0 {
		t.Fatalf("窃听轮次应记录窃听误码事实计数")
	}
}

// TestHighNoiseRejectedNotConfusedWithEve 高自然噪声超阈值时被拒，
// 但归因必须是自然噪声而非窃听。
func TestHighNoiseRejectedNotConfusedWithEve(t *testing.T) {
	cfg := DefaultRoundConfig()
	cfg.Channel.DepolarizationProb = 0.30 // 预期 QBER ~15% > 阈值 11%
	const seed = 555
	r := RunBB84Round(cfg, NewLockedSource(seed))
	logRound(t, "high-noise", seed, cfg, r)
	if r.Accepted {
		t.Fatalf("超阈值自然噪声应被拒绝")
	}
	if r.Reason != ReasonQBERTooHigh {
		t.Fatalf("高自然噪声拒绝原因应为 %s，得到 %s", ReasonQBERTooHigh, r.Reason)
	}
	if r.Attribution != AttributionNaturalNoise {
		t.Fatalf("高自然噪声归因应为 %s，得到 %s", AttributionNaturalNoise, r.Attribution)
	}
	if r.Key != nil {
		t.Fatalf("被拒轮次不得携带密钥材料")
	}
}

// TestPartialEavesdrop 部分拦截也应被归因为窃听（误码显著超出自然基线）。
func TestPartialEavesdrop(t *testing.T) {
	cfg := DefaultRoundConfig()
	cfg.Eve = EveConfig{Enabled: true, InterceptProb: 0.5}
	const seed = 2026
	r := RunBB84Round(cfg, NewLockedSource(seed))
	logRound(t, "partial-eve", seed, cfg, r)
	if r.Attribution != AttributionEavesdrop {
		t.Fatalf("50%% 拦截应被归因为窃听，得到 %s (qber=%.4f baseline=%.4f)",
			r.Attribution, r.QBER, r.NaturalBaseline)
	}
	if r.Accepted {
		t.Fatalf("50%% 拦截的误码率应超阈值并被拒绝")
	}
}

// TestInvalidParamsRejected 非法参数必须以 ReasonInvalidParams 拒绝。
func TestInvalidParamsRejected(t *testing.T) {
	cases := map[string]RoundConfig{
		"zero-pulses":      func() RoundConfig { c := DefaultRoundConfig(); c.NumPulses = 0; return c }(),
		"bad-sample":       func() RoundConfig { c := DefaultRoundConfig(); c.SampleFraction = 0; return c }(),
		"bad-threshold":    func() RoundConfig { c := DefaultRoundConfig(); c.QBERThreshold = 1.5; return c }(),
		"bad-min-sifted":   func() RoundConfig { c := DefaultRoundConfig(); c.MinSiftedBits = 0; return c }(),
		"bad-eve-prob":     func() RoundConfig { c := DefaultRoundConfig(); c.Eve = EveConfig{Enabled: true, InterceptProb: 1.5}; return c }(),
		"negative-loss":    func() RoundConfig { c := DefaultRoundConfig(); c.Channel.LossDB = -1; return c }(),
		"zero-det-eff":     func() RoundConfig { c := DefaultRoundConfig(); c.Channel.DetectorEfficiency = 0; return c }(),
		"dark-count-range": func() RoundConfig { c := DefaultRoundConfig(); c.Channel.DarkCountProb = 1; return c }(),
		"depol-range":      func() RoundConfig { c := DefaultRoundConfig(); c.Channel.DepolarizationProb = -0.1; return c }(),
	}
	for name, cfg := range cases {
		r := RunBB84Round(cfg, NewLockedSource(1))
		t.Logf("[invalid-%s] reason=%s", name, r.Reason)
		if r.Reason != ReasonInvalidParams {
			t.Fatalf("%s: 期望 %s，得到 %s", name, ReasonInvalidParams, r.Reason)
		}
		if r.Accepted || r.Key != nil {
			t.Fatalf("%s: 非法参数轮次不得被接受或携带密钥", name)
		}
	}
	// nil 随机源同样拒绝。
	if r := RunBB84Round(DefaultRoundConfig(), nil); r.Reason != ReasonInvalidParams {
		t.Fatalf("nil 随机源期望 %s，得到 %s", ReasonInvalidParams, r.Reason)
	}
}

// TestHighLossInsufficientKey 高损耗下筛选比特不足，必须明确失败。
func TestHighLossInsufficientKey(t *testing.T) {
	cfg := DefaultRoundConfig()
	cfg.NumPulses = 2000
	cfg.Channel.LossDB = 30 // 到达率极低
	const seed = 31
	r := RunBB84Round(cfg, NewLockedSource(seed))
	logRound(t, "high-loss", seed, cfg, r)
	if r.Accepted {
		t.Fatalf("高损耗短轮次不应产出密钥")
	}
	if r.Reason != ReasonInsufficientKey {
		t.Fatalf("期望 %s，得到 %s", ReasonInsufficientKey, r.Reason)
	}
	if r.Key != nil {
		t.Fatalf("失败轮次不得携带密钥材料")
	}
}

// TestLossAffectsKeyRate 损耗越大，最终密钥越短（单调趋势）。
func TestLossAffectsKeyRate(t *testing.T) {
	base := DefaultRoundConfig()
	base.NumPulses = 60000
	low := base
	high := base
	high.Channel.LossDB = base.Channel.LossDB + 6
	const seed = 77
	rLow := RunBB84Round(low, NewLockedSource(seed))
	rHigh := RunBB84Round(high, NewLockedSource(seed))
	logRound(t, "loss-low", seed, low, rLow)
	logRound(t, "loss-high", seed, high, rHigh)
	if !rLow.Accepted || !rHigh.Accepted {
		t.Fatalf("两种损耗都应可成钥：low=%s high=%s", rLow.Reason, rHigh.Reason)
	}
	if rHigh.FinalKeyBits >= rLow.FinalKeyBits {
		t.Fatalf("更高损耗应得到更短密钥：low=%d high=%d", rLow.FinalKeyBits, rHigh.FinalKeyBits)
	}
}
