package qkd

import (
	"encoding/binary"
	"hash/fnv"
	"math/rand"
	"sync"
)

// LockedSource 是并发安全的确定性随机源。
// 相同种子产生相同序列；Derive 基于标签确定性派生子流，
// 派生结果与调用顺序无关，因此并发使用仍可复现。
type LockedSource struct {
	mu   sync.Mutex
	src  *rand.Rand
	seed int64
}

// NewLockedSource 以给定种子创建随机源。
func NewLockedSource(seed int64) *LockedSource {
	return &LockedSource{src: rand.New(rand.NewSource(seed)), seed: seed}
}

// Derive 基于字符串标签确定性派生独立子随机源。
// 派生只依赖父种子与标签，不消耗父流，故与调用时序无关。
func (s *LockedSource) Derive(label string) *LockedSource {
	return NewLockedSource(deriveSeed(s.seed, label))
}

// Seed 返回创建该随机源的种子。
func (s *LockedSource) Seed() int64 { return s.seed }

// Intn 返回 [0,n) 内的随机整数。n <= 0 时返回 0。
func (s *LockedSource) Intn(n int) int {
	if n <= 0 {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.src.Intn(n)
}

// Float64 返回 [0,1) 内的随机浮点数。
func (s *LockedSource) Float64() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.src.Float64()
}

// Bit 返回随机比特 0 或 1。
func (s *LockedSource) Bit() int { return s.Intn(2) }

// Bytes 返回 n 字节随机数据。
func (s *LockedSource) Bytes(n int) []byte {
	if n <= 0 {
		return nil
	}
	out := make([]byte, n)
	s.mu.Lock()
	defer s.mu.Unlock()
	// rand.Rand.Read 是确定性的且永不返回错误。
	_, _ = s.src.Read(out)
	return out
}

// deriveSeed 由父种子与标签确定性地计算子种子（FNV-1a 混合）。
func deriveSeed(parent int64, label string) int64 {
	h := fnv.New64a()
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(parent))
	h.Write(buf[:])
	h.Write([]byte(label))
	return int64(h.Sum64())
}
