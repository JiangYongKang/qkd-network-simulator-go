package qkd

import (
	"errors"
	"fmt"
	"math"
)

// ChannelParams 描述一条本地光信道的物理参数。
type ChannelParams struct {
	// LossDB 信道损耗（分贝），必须 >= 0。
	LossDB float64
	// DetectorEfficiency 单光子探测器效率，取值 (0,1]。
	DetectorEfficiency float64
	// DarkCountProb 每个脉冲时隙内暗计数概率，取值 [0,1)。
	DarkCountProb float64
	// DepolarizationProb 自然去极化噪声概率，取值 [0,1)。
	DepolarizationProb float64
}

// DefaultChannelParams 返回一组典型的城域链路参数。
func DefaultChannelParams() ChannelParams {
	return ChannelParams{
		LossDB:             3.0,
		DetectorEfficiency: 0.2,
		DarkCountProb:      1e-5,
		DepolarizationProb: 0.01,
	}
}

// Validate 校验参数合法性。
func (p ChannelParams) Validate() error {
	if p.LossDB < 0 || math.IsNaN(p.LossDB) {
		return fmt.Errorf("channel: LossDB 必须 >= 0，得到 %v", p.LossDB)
	}
	if p.DetectorEfficiency <= 0 || p.DetectorEfficiency > 1 {
		return fmt.Errorf("channel: DetectorEfficiency 必须在 (0,1] 内，得到 %v", p.DetectorEfficiency)
	}
	if p.DarkCountProb < 0 || p.DarkCountProb >= 1 {
		return fmt.Errorf("channel: DarkCountProb 必须在 [0,1) 内，得到 %v", p.DarkCountProb)
	}
	if p.DepolarizationProb < 0 || p.DepolarizationProb >= 1 {
		return fmt.Errorf("channel: DepolarizationProb 必须在 [0,1) 内，得到 %v", p.DepolarizationProb)
	}
	return nil
}

// Transmittance 返回单个脉冲光子到达并被探测的总效率（不含暗计数）。
func (p ChannelParams) Transmittance() float64 {
	return math.Pow(10, -p.LossDB/10) * p.DetectorEfficiency
}

// ErrorCause 标记单个误码的物理来源（仿真内的“事实”）。
type ErrorCause int

const (
	CauseNone ErrorCause = iota
	CauseDepolarization
	CauseDarkCount
	CauseEavesdrop
)

func (c ErrorCause) String() string {
	switch c {
	case CauseNone:
		return "none"
	case CauseDepolarization:
		return "depolarization"
	case CauseDarkCount:
		return "dark-count"
	case CauseEavesdrop:
		return "eavesdrop"
	}
	return "unknown"
}

// Detection 表示一个脉冲时隙的探测结果。
type Detection struct {
	Detected  bool
	Bit       int
	DarkCount bool
	// Cause 仅当基矢匹配且结果比特与发送比特不同时非 CauseNone。
	Cause ErrorCause
}

// Channel 是本地光信道模型，负责光子传输与探测仿真。
type Channel struct {
	params ChannelParams
	rng    *LockedSource
}

// NewChannel 创建信道；参数非法时返回错误。
func NewChannel(p ChannelParams, rng *LockedSource) (*Channel, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if rng == nil {
		return nil, errors.New("channel: 随机源不能为空")
	}
	return &Channel{params: p, rng: rng}, nil
}

// Params 返回信道参数副本。
func (c *Channel) Params() ChannelParams { return c.params }

// Transmit 仿真发送一个比特（以 sendBasis 编码），接收方以 recvBasis 测量。
// 基矢不匹配时探测仍可能发生，但结果比特随机（该比特将在筛选阶段丢弃）。
func (c *Channel) Transmit(bit, sendBasis, recvBasis int) Detection {
	rng := c.rng
	matched := sendBasis == recvBasis
	depol := rng.Float64() < c.params.DepolarizationProb

	if rng.Float64() < c.params.Transmittance() {
		out := bit
		if !matched || depol {
			out = rng.Bit()
		}
		cause := CauseNone
		if matched && out != bit {
			// 基矢匹配下的信号误码只能来自去极化噪声。
			cause = CauseDepolarization
		}
		return Detection{Detected: true, Bit: out, Cause: cause}
	}
	if rng.Float64() < c.params.DarkCountProb {
		out := rng.Bit()
		cause := CauseNone
		if matched && out != bit {
			cause = CauseDarkCount
		}
		return Detection{Detected: true, Bit: out, DarkCount: true, Cause: cause}
	}
	return Detection{}
}
