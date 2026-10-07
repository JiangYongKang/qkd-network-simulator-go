package qkd

import (
	"fmt"
	"sync"
)

// PoolOverflowPolicy 定义密钥池装满时的处理规则。
type PoolOverflowPolicy int

const (
	// PoolRejectNew 池满时拒绝登记新密钥（该轮密钥被丢弃并记录）。
	PoolRejectNew PoolOverflowPolicy = iota
	// PoolQueue 池满时新密钥进入等待队列，有空间时按 FIFO 补入。
	PoolQueue
)

func (p PoolOverflowPolicy) String() string {
	switch p {
	case PoolRejectNew:
		return "reject-new"
	case PoolQueue:
		return "queue"
	}
	return "unknown"
}

// KeyRecord 是池中一条密钥登记记录。
type KeyRecord struct {
	// Round 产出该密钥的轮次编号。
	Round int
	Key   []byte
	// Consumed 为 true 表示已发放，不得再次发放。
	Consumed bool
}

// KeyPool 是多轮会话的统一密钥池，并发安全。
//
// 规则：
//   - 容量有上限；装满时按 PoolOverflowPolicy 处理（拒绝或排队）；
//   - Consume 按 FIFO 发放，已发放的密钥不会再次发放；
//   - 等待队列中的密钥在 Consume 释放空间时按 FIFO 补入可用池；
//   - Available 随时返回当前可发放的密钥数。
type KeyPool struct {
	mu       sync.Mutex
	capacity int
	policy   PoolOverflowPolicy
	records  []KeyRecord // 可用池中尚未发放的密钥（FIFO）
	pending  []KeyRecord // 等待队列（仅 PoolQueue 策略下非空）
	rejected int
}

// NewKeyPool 创建容量为 capacity 的密钥池。capacity <= 0 时返回 nil。
func NewKeyPool(capacity int, policy PoolOverflowPolicy) *KeyPool {
	if capacity <= 0 {
		return nil
	}
	return &KeyPool{capacity: capacity, policy: policy}
}

// Register 把一轮成功产出的密钥登记进池。
// 返回 true 表示进入可用池或等待队列；false 表示按 PoolRejectNew 被拒。
// 空密钥拒绝登记。
func (p *KeyPool) Register(round int, key []byte) bool {
	if p == nil || len(key) == 0 {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	rec := KeyRecord{Round: round, Key: append([]byte(nil), key...)}
	if len(p.records) < p.capacity {
		p.records = append(p.records, rec)
		return true
	}
	if p.policy == PoolQueue {
		p.pending = append(p.pending, rec)
		return true
	}
	p.rejected++
	return false
}

// Consume 按 FIFO 发放一条未消费的密钥；无可用密钥时返回 false。
// 已发放的密钥从池中移除，不会再次发放；发放释放出的容量位置
// 由等待队列中的最早一条按 FIFO 补入。
func (p *KeyPool) Consume() (KeyRecord, bool) {
	if p == nil {
		return KeyRecord{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.records) == 0 {
		return KeyRecord{}, false
	}
	rec := p.records[0]
	rec.Consumed = true
	p.records = p.records[1:]
	// 释放出一个容量位置，补入等待队列中的最早一条。
	if len(p.pending) > 0 {
		p.records = append(p.records, p.pending[0])
		p.pending = p.pending[1:]
	}
	return rec, true
}

// Available 返回当前可用（未消费）密钥数。
func (p *KeyPool) Available() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.records)
}

// Pending 返回等待队列中的密钥数。
func (p *KeyPool) Pending() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.pending)
}

// Rejected 返回因池满被拒的密钥数。
func (p *KeyPool) Rejected() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rejected
}

// Capacity 返回池容量上限。
func (p *KeyPool) Capacity() int {
	if p == nil {
		return 0
	}
	return p.capacity
}

// SessionResult 记录多轮会话的整体结果。
type SessionResult struct {
	// Rounds 是每一轮的中继结果（含失败轮次，失败轮次 Key 为空）。
	Rounds []RelayResult
	// Registered 是成功登记进池（含排队）的密钥数。
	Registered int
	// RejectedByPool 是因池满被 PoolRejectNew 策略丢弃的密钥数。
	RejectedByPool int
}

// RunSession 连续执行 rounds 轮中继，成功轮次的端到端密钥登记进 pool。
// 每轮使用按轮次标签派生的种子，整个序列由 seed 完全决定、可复现。
// pool 为 nil 时只执行轮次不登记。
func RunSession(nodes []Node, cfg RoundConfig, seed int64, rounds int, pool *KeyPool) SessionResult {
	res := SessionResult{}
	if rounds <= 0 {
		return res
	}
	res.Rounds = make([]RelayResult, rounds)
	for i := 0; i < rounds; i++ {
		roundSeed := deriveSeed(seed, fmt.Sprintf("session-round-%d", i))
		rr := RunRelayVerified(nodes, cfg, roundSeed)
		res.Rounds[i] = rr
		if !rr.Accepted || pool == nil {
			continue
		}
		if pool.Register(i, rr.Key) {
			res.Registered++
		} else {
			res.RejectedByPool++
		}
	}
	return res
}
