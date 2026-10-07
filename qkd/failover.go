package qkd

import "fmt"

// PathCandidate 是一条候选中继路径及其可用性模型。
type PathCandidate struct {
	Name  string
	Nodes []Node
	// DownAttempts 该路径的前若干次尝试不可用（模拟短时故障）。
	DownAttempts int
	// FlakyProb 每次尝试独立不可用的概率（时好时坏），取值 [0,1]。
	FlakyProb float64
}

// AttemptRecord 记录一次尝试的结论。
type AttemptRecord struct {
	Path    string
	Attempt int // 该路径上的第几次尝试（从 1 开始）
	// Outcome: "success" / "link-unavailable" / 协议拒绝原因字符串。
	Outcome string
	Reason  RejectReason
}

// FailoverResult 是切换与重试流程的最终结果。
type FailoverResult struct {
	Accepted bool
	Reason   RejectReason
	// Key 端到端密钥；失败时为空，绝不携带降级密钥。
	Key []byte
	// Path 成功产出密钥的路径名；失败时为空。
	Path     string
	Attempts []AttemptRecord
}

// RunWithFailover 在同一会话内按顺序尝试候选路径：
//
//   - 链路不可用（短时故障/时好时坏）时，在同一路径上重试，
//     最多 maxRetriesPerPath 次，用尽后切换到下一条候选路径；
//   - 协议层面被拒（窃听、参数不一致、节点不可信等）时不再重试，
//     直接切换到下一条候选路径；
//   - 任一尝试成功即产出端到端密钥并结束；
//   - 所有候选路径都不可用或不可信时，以 ReasonNoUsablePath 明确
//     失败，Key 恒为 nil，绝不把降级结果当成功。
//
// 每次尝试的可用性判定与中继随机性都由 seed 按
// "failover-<路径名>-<尝试序号>" 标签确定性派生，同一种子下
// 整个尝试序列完全可复现。
func RunWithFailover(paths []PathCandidate, cfg RoundConfig, seed int64, maxRetriesPerPath int) FailoverResult {
	res := FailoverResult{Reason: ReasonNone}
	if len(paths) == 0 || maxRetriesPerPath <= 0 || cfg.Validate() != nil {
		res.Reason = ReasonInvalidParams
		return res
	}
	for _, p := range paths {
		if p.FlakyProb < 0 || p.FlakyProb > 1 {
			res.Reason = ReasonInvalidParams
			return res
		}
	}
	root := NewLockedSource(seed)
	for _, p := range paths {
		for attempt := 1; attempt <= maxRetriesPerPath; attempt++ {
			label := fmt.Sprintf("failover-%s-%d", p.Name, attempt)
			avail := root.Derive(label + "-avail")
			rec := AttemptRecord{Path: p.Name, Attempt: attempt}
			down := attempt <= p.DownAttempts || avail.Float64() < p.FlakyProb
			if down {
				rec.Outcome = ReasonLinkUnavailable.String()
				rec.Reason = ReasonLinkUnavailable
				res.Attempts = append(res.Attempts, rec)
				continue // 链路不可用：同路径重试
			}
			relaySeed := root.Derive(label + "-relay").Seed()
			r, _ := RunRelayHandshake(p.Nodes, cfg, relaySeed)
			if r.Accepted {
				rec.Outcome = "success"
				rec.Reason = ReasonNone
				res.Attempts = append(res.Attempts, rec)
				res.Accepted = true
				res.Key = r.Key
				res.Path = p.Name
				return res
			}
			rec.Outcome = r.Reason.String()
			rec.Reason = r.Reason
			res.Attempts = append(res.Attempts, rec)
			break // 协议层面拒绝：该路径不可信，切换下一条
		}
	}
	res.Reason = ReasonNoUsablePath
	return res
}
