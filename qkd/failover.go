package qkd

import "fmt"

// 本文件实现链路异常时的路径切换与重试。
//
// 判定语义：同一会话内按顺序尝试多条候选路径，每条路径最多重试
// maxRetries 次（含首次）。某次尝试中路径被健康探针判定不可用，
// 或中继/逐跳核验失败，都记录为一次失败尝试并继续；任一尝试成功
// 即产出端到端密钥并结束。所有路径的所有尝试都失败时整体明确失败，
// 绝不把降级结果当作成功密钥产出。

// PathHealth 报告某条候选路径在第 attempt 次尝试时是否可用。
// 由调用方提供，便于模拟"时好时坏"的链路；应关于 (path, attempt) 确定，
// 以保证同一种子下整个序列可复现。nil 表示所有路径始终可用。
type PathHealth func(path, attempt int) bool

// PathAttempt 记录一次路径尝试的结论。
type PathAttempt struct {
	Path     int
	Attempt  int
	Accepted bool
	Reason   RejectReason
	Detail   string
}

// FailoverResult 是链路切换/重试的最终结论。
type FailoverResult struct {
	Accepted bool
	Reason   RejectReason
	// Key 端到端密钥；失败时为空。
	Key []byte
	// PathUsed 是最终产出密钥的候选路径下标，失败时为 -1。
	PathUsed int
	Attempts []PathAttempt
}

// RunRelayWithFailover 在同一会话内依次尝试多条候选路径：
// 每条路径最多重试 maxRetries 次（含首次）；healthy 报告不可用
// 或该次中继失败时切换/重试。任一尝试成功即产出密钥；
// 全部失败时以 ReasonNoUsablePath 明确失败，Key 为空。
// 每次尝试使用按 (路径, 尝试) 派生的种子，整体由 seed 决定、可复现。
func RunRelayWithFailover(paths [][]Node, cfg RoundConfig, seed int64, maxRetries int, healthy PathHealth) FailoverResult {
	res := FailoverResult{Reason: ReasonNone, PathUsed: -1}
	if len(paths) == 0 || maxRetries <= 0 || cfg.Validate() != nil {
		res.Reason = ReasonInvalidParams
		return res
	}
	for p, nodes := range paths {
		for a := 0; a < maxRetries; a++ {
			att := PathAttempt{Path: p, Attempt: a, Reason: ReasonNone}
			if healthy != nil && !healthy(p, a) {
				att.Reason = ReasonLinkUnavailable
				att.Detail = fmt.Sprintf("路径 %d 第 %d 次尝试时链路不可用", p, a)
				res.Attempts = append(res.Attempts, att)
				continue
			}
			attemptSeed := deriveSeed(seed, fmt.Sprintf("failover-p%d-a%d", p, a))
			rr := RunRelayVerified(nodes, cfg, attemptSeed)
			att.Accepted = rr.Accepted
			att.Reason = rr.Reason
			att.Detail = rr.Detail
			res.Attempts = append(res.Attempts, att)
			if rr.Accepted {
				res.Accepted = true
				res.Key = rr.Key
				res.PathUsed = p
				return res
			}
		}
	}
	res.Reason = ReasonNoUsablePath
	return res
}
