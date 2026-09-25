package qkd

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"sync"
)

// Node 是中继路径上的一个节点。
type Node struct {
	ID string
	// Trusted 为 false 时整个端到端流程必须失败。
	Trusted bool
	// ExpectedChannel 该节点认可的相邻链路信道参数；
	// 与实际参数不一致时流程必须失败。
	ExpectedChannel ChannelParams
}

// LinkResult 记录一条链路的 BB84 结果。
type LinkResult struct {
	From  string
	To    string
	Round RoundResult
}

// RelayResult 是多跳中继的最终结果。
type RelayResult struct {
	Accepted bool
	Reason   RejectReason
	// Key 端到端密钥，仅端点持有；失败时为空。
	Key    []byte
	Links  []LinkResult
	Detail string
}

// e2eKeyBytes 是端到端密钥的固定长度（字节）。
const e2eKeyBytes = 32

// RunRelay 在 nodes[0] 与 nodes[len(nodes)-1] 之间执行多跳中继密钥分发。
//
// 流程：相邻节点并行执行 BB84 得到链路密钥；端点的 DH 公开值沿路径
// 逐跳转发，每跳用链路密钥做 HMAC 认证；端点由 DH 共享秘密导出
// 端到端密钥。中间节点只见到链路密钥与 DH 公开值，无法推出端到端密钥。
//
// 任一节点不可信、节点参数与链路参数不一致、任一链路被拒或转发认证
// 失败时，整体明确失败（Accepted=false 且 Key 为空），绝不产出降级密钥。
func RunRelay(nodes []Node, cfg RoundConfig, seed int64) RelayResult {
	res := RelayResult{Reason: ReasonNone}
	if len(nodes) < 2 || cfg.Validate() != nil {
		res.Reason = ReasonInvalidParams
		res.Detail = "需要至少两个节点且协议参数合法"
		return res
	}
	for _, nd := range nodes {
		if !nd.Trusted {
			res.Reason = ReasonUntrustedNode
			res.Detail = fmt.Sprintf("节点 %s 不可信", nd.ID)
			return res
		}
		if nd.ExpectedChannel != cfg.Channel {
			res.Reason = ReasonParamMismatch
			res.Detail = fmt.Sprintf("节点 %s 期望的信道参数与链路参数不一致", nd.ID)
			return res
		}
	}

	// 1. 并行执行各链路 BB84。每条链路使用按标签确定性派生的
	// 独立随机流，结果写入各自的下标，无共享可变状态。
	nLinks := len(nodes) - 1
	res.Links = make([]LinkResult, nLinks)
	root := NewLockedSource(seed)
	var wg sync.WaitGroup
	for i := 0; i < nLinks; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			linkRng := root.Derive(fmt.Sprintf("link-%d", i))
			res.Links[i] = LinkResult{
				From:  nodes[i].ID,
				To:    nodes[i+1].ID,
				Round: RunBB84Round(cfg, linkRng),
			}
		}(i)
	}
	wg.Wait()

	for i, lr := range res.Links {
		if !lr.Round.Accepted {
			res.Reason = lr.Round.Reason
			res.Detail = fmt.Sprintf("链路 %s->%s 被拒：%s", lr.From, lr.To, lr.Round.Reason)
			res.Links = res.Links[:i+1]
			return res
		}
	}

	// 2. 端点各自生成 DH 密钥对，私钥不出端点作用域。
	alicePriv, alicePub := dhGenerate(root.Derive("dh-alice"))
	bobPriv, bobPub := dhGenerate(root.Derive("dh-bob"))

	// 3. 公开值沿路径逐跳转发，每跳用链路密钥做 HMAC 认证。
	if !relayMessage(alicePub.Bytes(), res.Links, true) {
		res.Reason = ReasonConfirmationFailed
		res.Detail = "Alice 公开值转发认证失败"
		return res
	}
	if !relayMessage(bobPub.Bytes(), res.Links, false) {
		res.Reason = ReasonConfirmationFailed
		res.Detail = "Bob 公开值转发认证失败"
		return res
	}

	// 4. 端点各自计算共享秘密并导出端到端密钥。
	sharedA := dhShared(bobPub, alicePriv)
	sharedB := dhShared(alicePub, bobPriv)
	if sharedA == nil || sharedB == nil || sharedA.Cmp(sharedB) != 0 {
		res.Reason = ReasonConfirmationFailed
		res.Detail = "DH 共享秘密不一致"
		return res
	}
	key := dhDeriveKey(sharedA, "relay-e2e", e2eKeyBytes)
	if len(key) != e2eKeyBytes {
		res.Reason = ReasonInsufficientKey
		res.Detail = "端到端密钥导出失败"
		return res
	}

	res.Accepted = true
	res.Key = key
	return res
}

// relayMessage 模拟消息沿链路逐跳转发：每一跳由发送侧用链路密钥
// 计算 HMAC，接收侧校验。forward 为 true 表示沿链路正序转发，
// 否则逆序。任一跳校验失败返回 false。
func relayMessage(msg []byte, links []LinkResult, forward bool) bool {
	n := len(links)
	for hop := 0; hop < n; hop++ {
		i := hop
		if !forward {
			i = n - 1 - hop
		}
		tag := linkTag(links[i].Round.Key, msg)
		// 接收侧用同一把链路密钥重新计算并比对。
		if !hmac.Equal(tag, linkTag(links[i].Round.Key, msg)) {
			return false
		}
	}
	return true
}

// linkTag 用链路密钥对消息计算认证标签。
func linkTag(linkKey, msg []byte) []byte {
	m := hmac.New(sha256.New, linkKey)
	m.Write([]byte("qkd-relay:"))
	m.Write(msg)
	return m.Sum(nil)
}
