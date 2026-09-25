// Package random provides a deterministic, concurrency-safe pseudorandom
// source for the whole simulation.
//
// # Design
//
// A Source is a SHA-256 counter-mode stream: block_i = SHA256(key || i),
// where key is derived deterministically from the full hierarchical
// derivation path (root seed -> labels). The mutable state is only a block
// counter protected by a mutex. Child sources are pure functions of the
// parent path and the label, so concurrent per-link/per-round rounds never
// race on a shared PRNG and results are exactly reproducible for a given
// seed regardless of goroutine scheduling.
package random

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math/bits"
	"sync"
)

// Source is a deterministic random source safe for concurrent use.
type Source struct {
	mu   sync.Mutex
	key  []byte // 32-byte stream key for this node in the derive tree
	path []byte // domain-separation path
	cnt  uint64 // next block counter
	tail []byte // unused bytes of the current block
}

// NewRoot creates a root stream from the given seed.
func NewRoot(seed int64) *Source {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], uint64(seed))
	h := sha256.New()
	h.Write([]byte("qkd-sim/root/v1"))
	h.Write(b[:])
	rootPath := h.Sum(nil)
	return &Source{key: streamKey(rootPath), path: rootPath}
}

// streamKey expands a derivation path into a 32-byte block key.
func streamKey(path []byte) []byte {
	h := sha256.New()
	h.Write([]byte("qkd-sim/ctr-key"))
	h.Write(path)
	return h.Sum(nil)
}

// Derive returns a deterministic child source for the given label.
func (s *Source) Derive(label string) *Source {
	h := sha256.New()
	h.Write(s.path)
	h.Write([]byte{'/'})
	h.Write([]byte(label))
	childPath := h.Sum(nil)
	return &Source{key: streamKey(childPath), path: childPath}
}

// nextBlockLocked produces the next 32-byte counter block.
func (s *Source) nextBlockLocked() []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], s.cnt)
	s.cnt++
	h := sha256.New()
	h.Write(s.key)
	h.Write(b[:])
	return h.Sum(nil)
}

// Read fills p with random bytes from the counter stream.
func (s *Source) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pos := 0
	for pos < len(p) {
		if len(s.tail) == 0 {
			s.tail = s.nextBlockLocked()
		}
		n := copy(p[pos:], s.tail)
		s.tail = s.tail[n:]
		pos += n
	}
	return len(p), nil
}

// Uint64 returns a pseudo-random 64-bit value.
func (s *Source) Uint64() uint64 {
	var b [8]byte
	if _, err := s.Read(b[:]); err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint64(b[:])
}

// Int63 returns a non-negative pseudo-random 63-bit integer.
func (s *Source) Int63() int64 {
	return int64(s.Uint64() & 0x7fffffffffffffff)
}

// Uint32 returns a pseudo-random 32-bit value.
func (s *Source) Uint32() uint32 {
	return uint32(s.Uint64())
}

// Intn returns an integer in [0,n); panics if n <= 0.
// It uses Lemire's nearly-divisionless method with rejection sampling,
// so the number of draws is data-dependent; callers that need an exact
// fixed number of stream blocks should use Read directly.
func (s *Source) Intn(n int) int {
	if n <= 0 {
		panic("random.Intn: non-positive n")
	}
	m := uint64(n)
	thresh := uint64(-m) % m // smallest representable multiple threshold
	for {
		v := s.Uint64()
		hi, lo := bits.Mul64(m, v)
		if lo >= thresh {
			return int(hi)
		}
	}
}

// Float64 returns a random float64 in [0,1).
func (s *Source) Float64() float64 {
	return float64(s.Uint64()>>11) / float64(1<<53)
}

// Bool returns true with probability p (clamped to [0,1]).
func (s *Source) Bool(p float64) bool {
	if p <= 0 {
		return false
	}
	if p >= 1 {
		return true
	}
	return s.Float64() < p
}

var _ io.Reader = (*Source)(nil)
