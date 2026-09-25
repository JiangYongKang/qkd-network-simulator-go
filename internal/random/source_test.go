package random

import (
	"bytes"
	"sync"
	"testing"
)

// TestDeterminism verifies that equal seeds produce identical streams even
// when sources are nested and consumed in different draw patterns.
func TestDeterminism(t *testing.T) {
	patterns := []func(s *Source){
		func(s *Source) {
			for i := 0; i < 1000; i++ {
				s.Intn(2)
			}
		},
		func(s *Source) {
			for i := 0; i < 500; i++ {
				s.Uint64()
				s.Float64()
			}
		},
		func(s *Source) {
			buf := make([]byte, 300)
			s.Read(buf)
		},
	}
	for pi, pat := range patterns {
		var a, b []byte
		for trial := 0; trial < 2; trial++ {
			root := NewRoot(99)
			c := root.Derive("hop1").Derive("channel")
			buf := make([]byte, 128)
			c.Read(buf[:64])
			pat(c)
			c.Read(buf[64:])
			if trial == 0 {
				a = buf
			} else {
				b = buf
			}
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("pattern %d non-deterministic", pi)
		}
		t.Logf("pattern %d deterministic, first bytes=%x", pi, a[:8])
	}
}

// TestDerivedChildrenAreIndependentAndStable verifies domain separation:
// different labels differ, and concurrent consumption cannot perturb a
// sibling stream.
func TestDerivedChildrenAreIndependentAndStable(t *testing.T) {
	r1 := NewRoot(1).Derive("a")
	r2 := NewRoot(1).Derive("b")
	r1same := NewRoot(1).Derive("a")
	b1 := make([]byte, 32)
	b2 := make([]byte, 32)
	b1s := make([]byte, 32)
	r1.Read(b1)
	r2.Read(b2)
	r1same.Read(b1s)
	if bytes.Equal(b1, b2) {
		t.Fatal("distinct labels collided")
	}
	if !bytes.Equal(b1, b1s) {
		t.Fatal("same label across roots diverged")
	}
}

// TestConcurrentNoInterference hammer-draws many child streams in parallel
// and verifies each child's full output matches a serial reference run.
func TestConcurrentNoInterference(t *testing.T) {
	const children = 16
	const rounds = 2000
	reference := func() [][]byte {
		root := NewRoot(777)
		out := make([][]byte, children)
		for i := 0; i < children; i++ {
			c := root.Derive("child" + itoa(i))
			buf := make([]byte, 0, rounds)
			for j := 0; j < rounds; j++ {
				buf = append(buf, byte(c.Intn(256)))
			}
			out[i] = buf
		}
		return out
	}
	want := reference()
	for trial := 0; trial < 5; trial++ {
		root := NewRoot(777)
		got := make([][]byte, children)
		var wg sync.WaitGroup
		for i := 0; i < children; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				c := root.Derive("child" + itoa(i))
				buf := make([]byte, 0, rounds)
				for j := 0; j < rounds; j++ {
					buf = append(buf, byte(c.Intn(256)))
				}
				got[i] = buf
			}(i)
		}
		wg.Wait()
		for i := range want {
			if !bytes.Equal(want[i], got[i]) {
				t.Fatalf("trial %d child %d perturbed by concurrency", trial, i)
			}
		}
	}
	t.Logf("seed=777 children=%d draws/child=%d concurrent runs match serial reference", children, rounds)
}

// TestIntnBounds checks bounds and rough uniformity of Intn.
func TestIntnBounds(t *testing.T) {
	s := NewRoot(5)
	counts := make([]int, 7)
	for i := 0; i < 70000; i++ {
		v := s.Intn(7)
		if v < 0 || v >= 7 {
			t.Fatalf("Intn out of range: %d", v)
		}
		counts[v]++
	}
	for v, c := range counts {
		if c < 7000 {
			t.Fatalf("bucket %d suspiciously low: %d", v, c)
		}
	}
	t.Logf("Intn(7) counts=%v seed=5", counts)
}

// TestBoolProbabilities checks p=0/p=1 clamping.
func TestBoolProbabilities(t *testing.T) {
	s := NewRoot(5)
	for i := 0; i < 100; i++ {
		if s.Bool(0) {
			t.Fatal("Bool(0) must be false")
		}
		if !s.Bool(1) {
			t.Fatal("Bool(1) must be true")
		}
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	p := len(buf)
	for i > 0 {
		p--
		buf[p] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[p:])
}
