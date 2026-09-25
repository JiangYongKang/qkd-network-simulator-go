// Package quantum models local optical-channel primitives: bases, photons,
// channel loss and detector events.
package quantum

import (
	"sync"

	"github.com/highcumontoa/qkd-network-simulator-go/internal/random"
)

// Bit is a raw binary value (0 or 1).
type Bit byte

// Basis selects an encoding basis: 0 = rectilinear, 1 = diagonal.
type Basis byte

const (
	BasisRect Basis = 0
	BasisDiag Basis = 1
)

// Photon is a prepared optical pulse: a bit encoded in a basis.
type Photon struct {
	Bit   Bit
	Basis Basis
}

// DetectorEvent is one detection outcome at the receiver for a given pulse.
type DetectorEvent struct {
	Index     int
	Bit       Bit
	Basis     Basis
	Clicked   bool
	DarkCount bool
	// EveTouched reports whether the pulse was intercepted and resent.
	EveTouched bool
	// OpticalFlip reports whether baseline optical misalignment flipped it.
	OpticalFlip bool
}

// ChannelParams describe the physical link.
type ChannelParams struct {
	Transmission       float64 // channel transmission probability in (0,1]
	DetectorEfficiency float64 // detector efficiency in (0,1]
	DarkCountRate      float64 // dark count probability per pulse in [0,1)
	OpticalBER         float64 // baseline optical misalignment error rate [0,1)
	EveIntercept       bool    // intercept-resend eavesdropper present
}

// DetectorState holds shared detector statistics, safe for concurrent use.
type DetectorState struct {
	mu      sync.Mutex
	signals int64
	darks   int64
	lost    int64
	eveHits int64
	flips   int64
}

// NewDetectorState creates an empty detector state.
func NewDetectorState() *DetectorState { return &DetectorState{} }

// Emit builds n photons: the sender picks each bit and basis at random.
func Emit(rng *random.Source, n int) ([]Photon, []Basis) {
	photons := make([]Photon, n)
	txBase := make([]Basis, n)
	for i := 0; i < n; i++ {
		b := Bit(rng.Intn(2))
		basis := Basis(rng.Intn(2))
		photons[i] = Photon{Bit: b, Basis: basis}
		txBase[i] = basis
	}
	return photons, txBase
}

// Transit applies (in order): intercept-resend eavesdropping, channel loss,
// detector efficiency, optical misalignment and dark counts. rxBase is the
// receiver's independently chosen measurement basis per pulse.
func Transit(rng *random.Source, photons []Photon, rxBase []Basis, p ChannelParams, state *DetectorState) []DetectorEvent {
	events := make([]DetectorEvent, len(photons))
	for i, ph := range photons {
		ev := DetectorEvent{Index: i, Basis: rxBase[i]}

		// State arriving at the receiver (possibly Eve's resent pulse).
		stateBit, stateBasis := ph.Bit, ph.Basis
		if p.EveIntercept {
			// Eve intercepts every pulse, measures in a random basis and
			// resends the projected state.
			eveBasis := Basis(rng.Intn(2))
			ev.EveTouched = true
			if state != nil {
				state.addEve()
			}
			if eveBasis == stateBasis {
				stateBit = ph.Bit
			} else {
				stateBit = Bit(rng.Intn(2))
			}
			stateBasis = eveBasis
		}

		signal := rng.Bool(p.Transmission) && rng.Bool(p.DetectorEfficiency)
		dark := rng.Bool(p.DarkCountRate)
		// Coincident signal and dark click: attribute to either source
		// with equal probability.
		if signal && dark {
			if rng.Bool(0.5) {
				dark = false
			} else {
				signal = false
			}
		}

		switch {
		case signal:
			ev.Clicked = true
			if state != nil {
				state.addSignal()
			}
			// Measurement in the receiver basis.
			if stateBasis == rxBase[i] {
				ev.Bit = stateBit
			} else {
				ev.Bit = Bit(rng.Intn(2))
			}
			// Baseline optical misalignment only matters when sender and
			// receiver bases match (it is a matched-basis error source).
			if ph.Basis == rxBase[i] && rng.Bool(p.OpticalBER) {
				ev.Bit ^= 1
				ev.OpticalFlip = true
				if state != nil {
					state.addFlip()
				}
			}
		case dark:
			ev.Clicked = true
			ev.DarkCount = true
			if state != nil {
				state.addDark()
			}
			// A dark count fires a random detector in the chosen basis.
			ev.Bit = Bit(rng.Intn(2))
		default:
			ev.Clicked = false
			if state != nil {
				state.addLost()
			}
		}
		events[i] = ev
	}
	return events
}

// Counts returns cumulative detector counts (for logs).
func (s *DetectorState) Counts() map[string]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]int64{
		"signal_clicks":   s.signals,
		"dark_clicks":     s.darks,
		"lost_pulses":     s.lost,
		"eve_intercepted": s.eveHits,
		"optical_flips":   s.flips,
	}
}

func (s *DetectorState) addSignal() { s.mu.Lock(); s.signals++; s.mu.Unlock() }
func (s *DetectorState) addDark()   { s.mu.Lock(); s.darks++; s.mu.Unlock() }
func (s *DetectorState) addLost()   { s.mu.Lock(); s.lost++; s.mu.Unlock() }
func (s *DetectorState) addEve()    { s.mu.Lock(); s.eveHits++; s.mu.Unlock() }
func (s *DetectorState) addFlip()   { s.mu.Lock(); s.flips++; s.mu.Unlock() }
