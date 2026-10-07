package qkd

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
)

// HopReport 是一跳链路某一侧给出的握手凭据：
// 由该侧认可的信道参数与链路密钥共同决定。
// 同一跳两侧的报告必须完全一致，否则端到端流程判定失败。
type HopReport struct {
	LinkIndex int
	Side      string // "left" 或 "right"
	Params    ChannelParams
	// Credential 绑定链路密钥、跳序号与信道参数的认证值。
	Credential []byte
}

// hopCredential 用链路密钥对（跳序号、信道参数）计算握手凭据。
// 两侧使用同一把链路密钥与相同的参数编码，只有参数一致时凭据才相等；
// 凭据与侧别无关，左右两侧应算出完全相同的值。
func hopCredential(linkKey []byte, linkIndex int, p ChannelParams) []byte {
	m := hmac.New(sha256.New, linkKey)
	m.Write([]byte("qkd-hop:"))
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], uint64(linkIndex))
	m.Write(idx[:])
	for _, v := range []float64{p.LossDB, p.DetectorEfficiency, p.DarkCountProb, p.DepolarizationProb} {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], math.Float64bits(v))
		m.Write(b[:])
	}
	return m.Sum(nil)
}

// BuildHopReports 由链路结果与协商参数构造每跳左、右两侧的握手报告。
// 仅对已接受的链路构造；报告按跳序号升序、每跳先左后右排列。
func BuildHopReports(links []LinkResult, ch ChannelParams) []HopReport {
	reports := make([]HopReport, 0, 2*len(links))
	for i, lr := range links {
		if !lr.Round.Accepted {
			continue
		}
		for _, side := range []string{"left", "right"} {
			reports = append(reports, HopReport{
				LinkIndex:  i,
				Side:       side,
				Params:     ch,
				Credential: hopCredential(lr.Round.Key, i, ch),
			})
		}
	}
	return reports
}

// VerifyHopReports 核验每跳两侧报告一致：跳序号连续完整、每跳恰好有
// 左右两份报告、两侧参数与凭据完全相同。返回 nil 表示一致；
// 否则返回描述性错误。
func VerifyHopReports(reports []HopReport) error {
	if len(reports) == 0 || len(reports)%2 != 0 {
		return fmt.Errorf("verify: 握手报告数量非法（%d）", len(reports))
	}
	for i := 0; i+1 < len(reports); i += 2 {
		l, r := reports[i], reports[i+1]
		if l.LinkIndex != i/2 || r.LinkIndex != i/2 {
			return fmt.Errorf("verify: 第 %d 跳报告缺失或乱序", i/2)
		}
		if l.Side != "left" || r.Side != "right" {
			return fmt.Errorf("verify: 第 %d 跳报告侧别非法（%s/%s）", i/2, l.Side, r.Side)
		}
		if l.Params != r.Params {
			return fmt.Errorf("verify: 第 %d 跳两侧信道参数不一致", i/2)
		}
		if !hmac.Equal(l.Credential, r.Credential) {
			return fmt.Errorf("verify: 第 %d 跳握手凭据不一致", i/2)
		}
	}
	return nil
}

// RunRelayHandshake 执行多跳中继，并为每一跳生成左、右两侧的握手报告；
// 只有全部跳的两侧报告两两一致时才产出端到端密钥，
// 否则以 ReasonHandshakeMismatch 失败且不携带任何密钥材料。
//
// 报告由中继流程内部构造并立即核验；返回报告副本供调用方审计或
// 独立复核（VerifyHopReports）。任何一跳对不上，整条端到端流程
// 直接判定失败，失败结果中 Key 恒为 nil。
func RunRelayHandshake(nodes []Node, cfg RoundConfig, seed int64) (RelayResult, []HopReport) {
	res := RunRelay(nodes, cfg, seed)
	if !res.Accepted {
		return res, nil
	}
	reports := BuildHopReports(res.Links, cfg.Channel)
	if err := VerifyHopReports(reports); err != nil {
		fail := RelayResult{
			Reason: ReasonHandshakeMismatch,
			Links:  res.Links,
			Detail: "逐跳一致性核验失败：" + err.Error(),
		}
		return fail, reports
	}
	return res, reports
}

// reportsEqual 比较两组报告是否完全一致（测试与可复现性核对用）。
func reportsEqual(a, b []HopReport) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].LinkIndex != b[i].LinkIndex || a[i].Side != b[i].Side ||
			a[i].Params != b[i].Params || !bytes.Equal(a[i].Credential, b[i].Credential) {
			return false
		}
	}
	return true
}
