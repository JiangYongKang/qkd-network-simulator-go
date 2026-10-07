package qkd

import (
	"crypto/hmac"
	"fmt"
)

// 本文件实现中继链路的逐跳一致性核验。
//
// 判定语义：对路径上的每一跳，逐一核对
//  1. 节点可信且其期望信道参数与会话参数一致（协商参数一致）；
//  2. 链路端点标识与路径一致、该跳 BB84 轮次被接受且持有非空链路密钥；
//  3. 正/反两个方向的握手凭据（HMAC）能用该跳链路密钥复算通过。
//
// 任一跳任一项对不上，该跳判定失败；存在失败跳时整条端到端流程
// 必须判定失败，且不得有任何密钥材料流向后续环节。

// HopCheck 记录一跳的核验结论。
type HopCheck struct {
	From   string
	To     string
	OK     bool
	Detail string
}

// VerifyRelayHops 对中继结果做逐跳一致性核验，返回每一跳的结论。
// 全部通过时返回的切片中所有 HopCheck.OK 均为 true。
func VerifyRelayHops(nodes []Node, cfg RoundConfig, r RelayResult) []HopCheck {
	if len(nodes) < 2 {
		return []HopCheck{{OK: false, Detail: "路径节点不足"}}
	}
	nLinks := len(nodes) - 1
	checks := make([]HopCheck, 0, nLinks)
	for i := 0; i < nLinks; i++ {
		chk := HopCheck{From: nodes[i].ID, To: nodes[i+1].ID, OK: true}
		fail := ""
		switch {
		case !nodes[i].Trusted || !nodes[i+1].Trusted:
			fail = "节点不可信"
		case nodes[i].ExpectedChannel != cfg.Channel || nodes[i+1].ExpectedChannel != cfg.Channel:
			fail = "节点期望信道参数与会话参数不一致"
		case i >= len(r.Links):
			fail = "缺少该跳的链路结果"
		case r.Links[i].From != nodes[i].ID || r.Links[i].To != nodes[i+1].ID:
			fail = "链路端点标识与路径不一致"
		case !r.Links[i].Round.Accepted:
			fail = fmt.Sprintf("该跳 BB84 轮次被拒：%s", r.Links[i].Round.Reason)
		case len(r.Links[i].Round.Key) == 0:
			fail = "该跳链路密钥为空"
		case !hmac.Equal(r.Links[i].FwdTag, linkTag(r.Links[i].Round.Key, r.HandshakeFwd)):
			fail = "正向握手凭据复算不一致"
		case !hmac.Equal(r.Links[i].BwdTag, linkTag(r.Links[i].Round.Key, r.HandshakeBwd)):
			fail = "反向握手凭据复算不一致"
		}
		if fail != "" {
			chk.OK = false
			chk.Detail = fail
		} else {
			chk.Detail = "参数、轮次结果与握手凭据一致"
		}
		checks = append(checks, chk)
	}
	return checks
}

// hopsAllOK 报告所有跳是否核验通过。
func hopsAllOK(checks []HopCheck) bool {
	for _, c := range checks {
		if !c.OK {
			return false
		}
	}
	return true
}

// firstFailedHop 返回第一跳核验失败的描述；全部通过时返回空串。
func firstFailedHop(checks []HopCheck) string {
	for _, c := range checks {
		if !c.OK {
			return fmt.Sprintf("链路 %s->%s 核验失败：%s", c.From, c.To, c.Detail)
		}
	}
	return ""
}

// RunRelayVerified 执行中继并对结果做逐跳核验；任一跳核验失败时
// 整体判定失败（Accepted=false、Key 为空、Reason=ReasonHopVerifyFailed），
// 密钥材料不进入后续环节。绝不产出降级密钥。
func RunRelayVerified(nodes []Node, cfg RoundConfig, seed int64) RelayResult {
	res := RunRelay(nodes, cfg, seed)
	if !res.Accepted {
		return res
	}
	checks := VerifyRelayHops(nodes, cfg, res)
	if !hopsAllOK(checks) {
		res.Accepted = false
		res.Reason = ReasonHopVerifyFailed
		res.Detail = firstFailedHop(checks)
		res.Key = nil
		return res
	}
	return res
}
