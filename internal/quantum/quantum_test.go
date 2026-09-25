package quantum

import (
	"sync"
	"testing"

	"github.com/highcumontoa/qkd-network-simulator-go/internal/random"
)

// TestEmit checks emission shape and reproducibility.
func TestEmit(t *testing.T) {
	r1 := random.NewRoot(1)
	ph1, b1 := Emit(r1, 2000)
	ph2, b2 := Emit(random.NewRoot(1), 2000)
	if len(ph1) != 2000 || len(b1) != 2000 {
		t.Fatal("emission length mismatch")
	}
	for i := range ph1 {
		if ph1[i].Bit != ph2[i].Bit || ph1[i].Basis != ph2[i].Basis || b1[i] != b2[i] {
			t.Fatal("emission not reproducible under same seed")
		}
		if ph1[i].Bit > 1 || ph1[i].Basis > 1 {
			t.Fatal("emitted value out of {0,1}")
		}
	}
	t.Log("emission reproducible for seed=1, n=2000")
}

// TestChannelLossReducesClicks verifies transmission/efficiency gate clicks.
func TestChannelLossReducesClicks(t *testing.T) {
	n := 8000
	pp := ChannelParams{Transmission: 1, DetectorEfficiency: 1, DarkCountRate: 0}
	lowPP := ChannelParams{Transmission: 0.3, DetectorEfficiency: 0.5, DarkCountRate: 0}
	count := func(p ChannelParams) int {
		rng := random.NewRoot(9)
		ph, _ := Emit(rng, n)
		rx := make([]Basis, n)
		for i := range rx {
			rx[i] = Basis(rng.Intn(2))
		}
		evs := Transit(rng, ph, rx, p, nil)
		c := 0
		for _, e := range evs {
			if e.Clicked {
				c++
			}
		}
		return c
	}
	hi := count(pp)
	lo := count(lowPP)
	t.Logf("high-eff clicks=%d low-eff clicks=%d (n=%d)", hi, lo, n)
	if lo >= hi {
		t.Fatal("lower transmission/efficiency must reduce clicks")
	}
	// High-eff, no dark counts: click rate should be ~50% (basis match) of all.
	if hi < n/3 {
		t.Fatalf("ideal channel click count unexpectedly low: %d", hi)
	}
}

// TestDarkCountsDetected verifies dark counts are flagged and add clicks.
func TestDarkCountsDetected(t *testing.T) {
	n := 4000
	noDark := ChannelParams{Transmission: 0, DetectorEfficiency: 1, DarkCountRate: 0}
	withDark := ChannelParams{Transmission: 0, DetectorEfficiency: 1, DarkCountRate: 0.3}
	run := func(p ChannelParams) (int, int) {
		rng := random.NewRoot(3)
		ph, _ := Emit(rng, n)
		rx := make([]Basis, n)
		for i := range rx {
			rx[i] = Basis(rng.Intn(2))
		}
		state := NewDetectorState()
		evs := Transit(rng, ph, rx, p, state)
		clicks, darks := 0, 0
		for _, e := range evs {
			if e.Clicked {
				clicks++
			}
			if e.DarkCount {
				darks++
			}
		}
		return clicks, darks
	}
	c0, d0 := run(noDark)
	c1, d1 := run(withDark)
	t.Logf("noDark: clicks=%d darks=%d | withDark: clicks=%d darks=%d", c0, d0, c1, d1)
	if c0 != 0 || d0 != 0 {
		t.Fatal("zero transmission and zero dark counts must yield no clicks")
	}
	if d1 == 0 || d1 != c1 {
		t.Fatal("with zero transmission all clicks must be flagged dark counts")
	}
}

// TestEavesdropperTouchesPulses verifies the model flags intercepted pulses
// and measurably perturbs matched-basis outcomes.
func TestEavesdropperTouchesPulses(t *testing.T) {
	n := 8000
	cp := ChannelParams{Transmission: 1, DetectorEfficiency: 1, DarkCountRate: 0}
	rng := random.NewRoot(123)
	ph, txBase := Emit(rng, n)
	// Receiver measures in the sender basis always: without Eve, zero errors.
	matchedRx := append([]Basis{}, txBase...)

	clean := Transit(rng, ph, matchedRx, cp, nil)
	errs := 0
	for _, e := range clean {
		if e.Clicked && e.Bit != ph[e.Index].Bit {
			errs++
		}
	}
	t.Logf("clean matched-basis errors=%d", errs)
	if errs != 0 {
		t.Fatalf("ideal channel with matched bases must be error-free, got %d", errs)
	}

	cp.EveIntercept = true
	state := NewDetectorState()
	evs := Transit(random.NewRoot(123), ph, matchedRx, cp, state)
	eveErrs, touched := 0, 0
	for _, e := range evs {
		if !e.EveTouched {
			t.Fatal("every pulse should be flagged as intercepted")
		}
		touched++
		if e.Clicked && e.Bit != ph[e.Index].Bit {
			eveErrs++
		}
	}
	t.Logf("eve: touched=%d matched-basis errors=%d (expect ~25%% of clicks)", touched, eveErrs)
	if touched != n {
		t.Fatal("Eve should intercept every pulse")
	}
	if eveErrs == 0 {
		t.Fatal("intercept-resend at random bases must cause matched-basis errors")
	}
	counts := state.Counts()
	if counts["eve_intercepted"] != int64(n) {
		t.Fatalf("detector state eve count=%d want %d", counts["eve_intercepted"], n)
	}
}

// TestDetectorStateConcurrentSafe hammers the shared detector state.
func TestDetectorStateConcurrentSafe(t *testing.T) {
	state := NewDetectorState()
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				state.addSignal()
				state.addDark()
				state.addLost()
				state.addFlip()
				state.addEve()
			}
		}()
	}
	wg.Wait()
	c := state.Counts()
	for k, v := range c {
		if v != 16000 {
			t.Fatalf("counter %s = %d, want 16000", k, v)
		}
	}
	t.Logf("shared detector state under 16 goroutines: %v", c)
}
