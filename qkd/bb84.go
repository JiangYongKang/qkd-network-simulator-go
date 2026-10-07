package qkd

import (
	"bytes"
	"errors"
	"fmt"
	"math"
)

// RejectReason 区分一轮密钥分发的失败原因。
type RejectReason int

const (
	ReasonNone RejectReason = iota
	ReasonInvalidParams
	ReasonInsufficientKey
	ReasonQBERTooHigh
	ReasonEavesdropSuspected
	ReasonConfirmationFailed
	ReasonUntrustedNode
	ReasonParamMismatch
	// ReasonHopVerifyFailed 逐跳一致性核验未通过。
	ReasonHopVerifyFailed
	// ReasonLinkUnavailable 链路/路径当前不可用（切换重试场景）。
	ReasonLinkUnavailable
	// ReasonNoUsablePath 所有候选路径均不可信或不可用。
	ReasonNoUsablePath
)

func (r RejectReason) String() string {
	switch r {
	case ReasonNone:
		return "none"
	case ReasonInvalidParams:
		return "invalid-params"
	case ReasonInsufficientKey:
		return "insufficient-key"
	case ReasonQBERTooHigh:
		return "qber-too-high"
	case ReasonEavesdropSuspected:
		return "eavesdrop-suspected"
	case ReasonConfirmationFailed:
		return "confirmation-failed"
	case ReasonUntrustedNode:
		return "untrusted-node"
	case ReasonParamMismatch:
		return "param-mismatch"
	case ReasonHopVerifyFailed:
		return "hop-verify-failed"
	case ReasonLinkUnavailable:
		return "link-unavailable"
	case ReasonNoUsablePath:
		return "no-usable-path"
	}
	return "unknown"
}

// ErrorAttribution 给出误码来源的判定结论。
type ErrorAttribution int

const (
	AttributionNone ErrorAttribution = iota
	AttributionNaturalNoise
	AttributionEavesdrop
)

func (a ErrorAttribution) String() string {
	switch a {
	case AttributionNone:
		return "none"
	case AttributionNaturalNoise:
		return "natural-noise"
	case AttributionEavesdrop:
		return "eavesdrop"
	}
	return "unknown"
}

// EveConfig 描述拦截-重发式窃听。
type EveConfig struct {
	Enabled bool
	// InterceptProb 每个脉冲被拦截的概率，取值 [0,1]。
	InterceptProb float64
}

// RoundConfig 是一轮 BB84 的全部协议参数。
type RoundConfig struct {
	// NumPulses 发送的脉冲数，必须 > 0。
	NumPulses int
	Channel   ChannelParams
	Eve       EveConfig
	// SampleFraction 用于误码率估计的筛选密钥抽样比例，取值 (0,1)。
	SampleFraction float64
	// QBERThreshold 可接受的最大误码率，取值 (0,1)。
	QBERThreshold float64
	// MinSiftedBits 进入后处理所需的最少筛选比特数。
	MinSiftedBits int
	// SecurityBits 隐私放大安全余量（比特）。
	SecurityBits int
}

// DefaultRoundConfig 返回默认协议参数。
func DefaultRoundConfig() RoundConfig {
	return RoundConfig{
		NumPulses:      20000,
		Channel:        DefaultChannelParams(),
		SampleFraction: 0.2,
		QBERThreshold:  0.11,
		MinSiftedBits:  256,
		SecurityBits:   32,
	}
}

// Validate 校验协议参数。
func (c RoundConfig) Validate() error {
	if c.NumPulses <= 0 {
		return fmt.Errorf("bb84: NumPulses 必须 > 0，得到 %d", c.NumPulses)
	}
	if err := c.Channel.Validate(); err != nil {
		return err
	}
	if c.Eve.InterceptProb < 0 || c.Eve.InterceptProb > 1 {
		return fmt.Errorf("bb84: Eve.InterceptProb 必须在 [0,1] 内，得到 %v", c.Eve.InterceptProb)
	}
	if c.SampleFraction <= 0 || c.SampleFraction >= 1 {
		return fmt.Errorf("bb84: SampleFraction 必须在 (0,1) 内，得到 %v", c.SampleFraction)
	}
	if c.QBERThreshold <= 0 || c.QBERThreshold >= 1 {
		return fmt.Errorf("bb84: QBERThreshold 必须在 (0,1) 内，得到 %v", c.QBERThreshold)
	}
	if c.MinSiftedBits <= 0 {
		return fmt.Errorf("bb84: MinSiftedBits 必须 > 0，得到 %d", c.MinSiftedBits)
	}
	if c.SecurityBits < 0 {
		return fmt.Errorf("bb84: SecurityBits 必须 >= 0，得到 %d", c.SecurityBits)
	}
	return nil
}

// RoundResult 记录一轮 BB84 的完整结果与判定依据。
type RoundResult struct {
	Accepted bool
	Reason   RejectReason
	// Attribution 误码来源判定（自然噪声 / 窃听）。
	Attribution ErrorAttribution
	// Key 仅在 Accepted 为 true 时非空。
	Key []byte

	PulsesSent   int
	SiftedBits   int
	SampleBits   int
	SampleErrors int
	QBER         float64
	// NaturalBaseline 由信道参数推导的自然噪声误码率基线。
	NaturalBaseline float64

	// 仿真“事实”计数，用于测试与解释。
	TrueNoiseErrors int
	TrueEveErrors   int

	CorrectedBits int
	LeakedBits    int
	FinalKeyBits  int
}

// naturalBaseline 由信道参数推导基矢匹配条件下的期望自然误码率。
func naturalBaseline(p ChannelParams) float64 {
	sig := p.Transmittance()
	dark := p.DarkCountProb
	if sig+dark <= 0 {
		return 0
	}
	// 信号贡献 depol/2 的误码，暗计数贡献 1/2 的误码。
	return (sig*p.DepolarizationProb/2 + dark*0.5) / (sig + dark)
}

// RunBB84Round 在发送端与接收端之间执行一轮完整 BB84 流程：
// 编码、（可选的）拦截-重发窃听、信道传输、筛选、误码率估计、
// 窃听判定、纠错、隐私放大与确认。
// 被判定为不可接受的轮次不会携带任何密钥材料（Key 恒为 nil）。
func RunBB84Round(cfg RoundConfig, rng *LockedSource) RoundResult {
	res := RoundResult{Reason: ReasonNone}
	if rng == nil || cfg.Validate() != nil {
		res.Reason = ReasonInvalidParams
		return res
	}

	// 各角色使用确定性派生的独立子流，与并发调度无关。
	aRng := rng.Derive("alice")
	bRng := rng.Derive("bob")
	eRng := rng.Derive("eve")
	sRng := rng.Derive("sample")
	ch, err := NewChannel(cfg.Channel, rng.Derive("channel"))
	if err != nil {
		res.Reason = ReasonInvalidParams
		return res
	}

	n := cfg.NumPulses
	res.PulsesSent = n

	// 1. 编码：Alice 随机选择比特与基矢；Bob 随机选择测量基矢。
	aliceBits := make([]int, n)
	aliceBases := make([]int, n)
	for i := range aliceBits {
		aliceBits[i] = aRng.Bit()
		aliceBases[i] = aRng.Bit()
	}
	bobBases := make([]int, n)
	for i := range bobBases {
		bobBases[i] = bRng.Bit()
	}

	// 2. 传输（可选窃听）与探测。
	var siftAlice, siftBob []int
	for i := 0; i < n; i++ {
		bit, basis := aliceBits[i], aliceBases[i]
		intercepted := false
		if cfg.Eve.Enabled && eRng.Float64() < cfg.Eve.InterceptProb {
			// 拦截-重发：Eve 随机选基测量并重发。
			intercepted = true
			eveBasis := eRng.Bit()
			eveBit := bit
			if eveBasis != basis {
				eveBit = eRng.Bit()
			}
			bit, basis = eveBit, eveBasis
		}
		det := ch.Transmit(bit, basis, bobBases[i])
		if !det.Detected || bobBases[i] != aliceBases[i] {
			continue // 未探测或基矢不匹配，筛选阶段丢弃
		}
		// 基矢匹配下的误码“事实”归因。
		if det.Bit != aliceBits[i] {
			if det.Cause == CauseNone && intercepted {
				det.Cause = CauseEavesdrop
			}
			switch det.Cause {
			case CauseEavesdrop:
				res.TrueEveErrors++
			default:
				res.TrueNoiseErrors++
			}
		}
		siftAlice = append(siftAlice, aliceBits[i])
		siftBob = append(siftBob, det.Bit)
	}
	res.SiftedBits = len(siftAlice)
	res.NaturalBaseline = naturalBaseline(cfg.Channel)

	if res.SiftedBits < cfg.MinSiftedBits {
		res.Reason = ReasonInsufficientKey
		return res
	}

	// 3. 误码率估计：随机抽样并公开比对，抽样比特从密钥中移除。
	var keyA, keyB []int
	for i := 0; i < res.SiftedBits; i++ {
		if sRng.Float64() < cfg.SampleFraction {
			res.SampleBits++
			if siftAlice[i] != siftBob[i] {
				res.SampleErrors++
			}
			continue
		}
		keyA = append(keyA, siftAlice[i])
		keyB = append(keyB, siftBob[i])
	}
	if res.SampleBits == 0 {
		res.Reason = ReasonInsufficientKey
		return res
	}
	res.QBER = float64(res.SampleErrors) / float64(res.SampleBits)

	// 4. 窃听判定：显著超出自然基线（5σ 抽样涨落边际）归因于窃听，
	// 否则归因于自然噪声。σ 以基线误码率估计，且基线不低于 1/样本数，
	// 避免小样本下把统计涨落误判为窃听。
	p0 := res.NaturalBaseline
	if floor := 1.0 / float64(res.SampleBits); p0 < floor {
		p0 = floor
	}
	margin := 5 * math.Sqrt(p0*(1-p0)/float64(res.SampleBits))
	if res.QBER > res.NaturalBaseline+margin {
		res.Attribution = AttributionEavesdrop
	} else if res.QBER > 0 {
		res.Attribution = AttributionNaturalNoise
	}
	if res.QBER > cfg.QBERThreshold {
		if res.Attribution == AttributionEavesdrop {
			res.Reason = ReasonEavesdropSuspected
		} else {
			res.Reason = ReasonQBERTooHigh
		}
		return res
	}

	// 5. 纠错：Cascade 式分块奇偶校验 + 二分定位翻转，
	// 不删除比特，只统计泄露的奇偶比特数。
	corrA, corrB, leaked := cascadeCorrect(keyA, keyB, res.QBER, rng.Derive("ec"))
	res.CorrectedBits = len(corrA)
	res.LeakedBits = leaked

	// 6. 隐私放大：按可密钥率压缩，长度不为负、不凭空增长。
	finalBits := int(math.Floor(float64(len(corrA))*(1-h2(res.QBER)))) - leaked - cfg.SecurityBits
	if finalBits <= 0 {
		res.Reason = ReasonInsufficientKey
		return res
	}
	res.FinalKeyBits = finalBits
	keyBytesA := privacyAmplify(corrA, finalBits, "bb84")
	keyBytesB := privacyAmplify(corrB, finalBits, "bb84")

	// 7. 密钥确认：双方独立计算确认标签并比对。
	if !bytes.Equal(confirmationTag(keyBytesA, "alice"), confirmationTag(keyBytesB, "alice")) ||
		!bytes.Equal(keyBytesA, keyBytesB) {
		res.Reason = ReasonConfirmationFailed
		res.FinalKeyBits = 0
		return res
	}

	res.Accepted = true
	res.Reason = ReasonNone
	res.Key = keyBytesA
	return res
}

// errRejected 便于在组合流程中把拒绝原因包装为错误。
func errRejected(r RejectReason, ctx string) error {
	return fmt.Errorf("%s: %w", ctx, errors.New(r.String()))
}
