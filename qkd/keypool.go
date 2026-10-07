package qkd

import (
	"errors"
	"fmt"
	"sync"
)

// OverflowPolicy 定义密钥池装满后的处理规则。
type OverflowPolicy int

const (
	// OverflowReject 池满时拒绝登记新密钥（该轮密钥被丢弃并记录）。
	OverflowReject OverflowPolicy = iota
	// OverflowDropOldest 池满时丢弃最旧的未消费密钥，登记新密钥。
	OverflowDropOldest
)

func (p OverflowPolicy) String() string {
	switch p {
	case OverflowReject:
		return "reject"
	case OverflowDropOldest:
		return "drop-oldest"
	}
	return "unknown"
}

// PoolEntry 是池中的一条密钥记录。
type PoolEntry struct {
	// Round 产出该密钥的会话轮次。
	Round int
	Key   []byte
}

// PoolStats 是密钥池的累计统计。
type PoolStats struct {
	Deposited int // 成功登记进池的密钥数
	Dropped   int // 因池满被丢弃（拒绝或顶替）的密钥数
	Consumed  int // 被消费发放的密钥数
}

// KeyPool 是多轮会话的统一密钥池，并发安全。
// 已发放的密钥即从池中移除，不会再次发放。
type KeyPool struct {
	mu       sync.Mutex
	capacity int
	policy   OverflowPolicy
	entries  []PoolEntry
	stats    PoolStats
}

// NewKeyPool 创建容量为 capacity 的密钥池；capacity 必须 > 0。
func NewKeyPool(capacity int, policy OverflowPolicy) (*KeyPool, error) {
	if capacity <= 0 {
		return nil, fmt.Errorf("keypool: 容量必须 > 0，得到 %d", capacity)
	}
	if policy != OverflowReject && policy != OverflowDropOldest {
		return nil, fmt.Errorf("keypool: 未知的溢出策略 %d", int(policy))
	}
	return &KeyPool{capacity: capacity, policy: policy}, nil
}

// Capacity 返回池容量上限。
func (p *KeyPool) Capacity() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.capacity
}

// Deposit 把一轮产出的密钥登记进池。
// 返回 false 表示池满且策略为 OverflowReject，密钥被丢弃；
// 策略为 OverflowDropOldest 时丢弃最旧条目后登记，返回 true。
// 空密钥（nil）拒绝登记。
func (p *KeyPool) Deposit(round int, key []byte) bool {
	if len(key) == 0 {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.entries) >= p.capacity {
		if p.policy == OverflowReject {
			p.stats.Dropped++
			return false
		}
		// 丢弃最旧的未消费密钥，腾出席位。
		p.entries = p.entries[1:]
		p.stats.Dropped++
	}
	stored := make([]byte, len(key))
	copy(stored, key)
	p.entries = append(p.entries, PoolEntry{Round: round, Key: stored})
	p.stats.Deposited++
	return true
}

// Consume 取出最旧的一条可用密钥并从池中移除。
// 第二个返回值表示是否取到；取到的密钥不会再被发放。
func (p *KeyPool) Consume() (PoolEntry, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.entries) == 0 {
		return PoolEntry{}, false
	}
	e := p.entries[0]
	p.entries = p.entries[1:]
	p.stats.Consumed++
	return e, true
}

// Available 返回当前池中可用（未发放）的密钥条数。
func (p *KeyPool) Available() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries)
}

// Stats 返回累计统计副本。
func (p *KeyPool) Stats() PoolStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stats
}

// SessionConfig 描述一个多轮密钥分发会话。
type SessionConfig struct {
	// Rounds 会话轮次数，必须 > 0。
	Rounds int
	// Nodes 中继路径（每轮相同）。
	Nodes []Node
	// Relay 每轮的协议参数。
	Relay RoundConfig
	// ConsumeEvery 每完成多少轮就从池中消费一条密钥；0 表示不消费。
	ConsumeEvery int
}

// Validate 校验会话参数。
func (c SessionConfig) Validate() error {
	if c.Rounds <= 0 {
		return fmt.Errorf("session: Rounds 必须 > 0，得到 %d", c.Rounds)
	}
	if len(c.Nodes) < 2 {
		return errors.New("session: 需要至少两个节点")
	}
	if c.ConsumeEvery < 0 {
		return fmt.Errorf("session: ConsumeEvery 必须 >= 0，得到 %d", c.ConsumeEvery)
	}
	return c.Relay.Validate()
}

// RoundRecord 记录一轮的产出与消费情况。
type RoundRecord struct {
	Round     int
	Accepted  bool
	Reason    RejectReason
	Deposited bool // 密钥是否成功入池（false 且 Accepted 表示池满被拒）
	Consumed  bool // 本轮结束后是否消费了一条密钥
}

// SessionResult 是整个多轮会话的结果。
type SessionResult struct {
	Records        []RoundRecord
	Stats          PoolStats
	FinalAvailable int
}

// RunSession 执行多轮会话：每轮在 Nodes 上跑中继，成功则把端到端密钥
// 按轮次登记进 pool，并按 ConsumeEvery 的节奏消费。同一种子下整个
// 序列（产出与消费记录）完全可复现。
func RunSession(cfg SessionConfig, pool *KeyPool, seed int64) SessionResult {
	res := SessionResult{}
	if cfg.Validate() != nil || pool == nil {
		return res
	}
	res.Records = make([]RoundRecord, 0, cfg.Rounds)
	for i := 0; i < cfg.Rounds; i++ {
		rec := RoundRecord{Round: i, Reason: ReasonNone}
		roundSeed := deriveSeed(seed, fmt.Sprintf("session-round-%d", i))
		r := RunRelay(cfg.Nodes, cfg.Relay, roundSeed)
		rec.Accepted = r.Accepted
		rec.Reason = r.Reason
		if r.Accepted {
			rec.Deposited = pool.Deposit(i, r.Key)
		}
		if cfg.ConsumeEvery > 0 && (i+1)%cfg.ConsumeEvery == 0 {
			_, rec.Consumed = pool.Consume()
		}
		res.Records = append(res.Records, rec)
	}
	res.Stats = pool.Stats()
	res.FinalAvailable = pool.Available()
	return res
}
