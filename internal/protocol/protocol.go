// Package protocol implements the BB84-style point-to-point QKD simulation:
// sifting, QBER estimation, rejection, error correction and privacy amplification.
package protocol

import (
	"errors"
	"fmt"
	"math"

	"github.com/highcumontoa/qkd-network-simulator-go/internal/quantum"
	"github.com/highcumontoa/qkd-network-simulator-go/internal/random"
)

// RejectReason states why a round was rejected (empty for accepted rounds).
type RejectReason string

const (
	ReasonNone                 RejectReason = ""
	ReasonInvalidParams        RejectReason = "invalid_parameters"
	ReasonInsufficientBits     RejectReason = "insufficient_sifted_bits"
	ReasonEavesdropping        RejectReason = "eavesdropping_detected"
	ReasonQBERThreshold        RejectReason = "natural_qber_above_threshold"
	ReasonNonPositiveKey       RejectReason = "non_positive_key_length"
	ReasonUntrustedNode        RejectReason = "untrusted_node"
	ReasonConfirmationMismatch RejectReason = "end_to_end_confirmation_mismatch"
)

// Params are the protocol-level parameters shared by every node on a path.
type Params struct {
	PulseCount       int     // number of pulses emitted by the sender
	EstimateFraction float64 // fraction of sifted bits sacrificed for QBER estimation
	QBERThreshold    float64 // hard QBER limit; above it the round is rejected
	NoiseConfidenceZ float64 // z-score separating natural noise from eavesdropping
	MinSifted        int     // minimum matched-basis clicks required
	CorrectableBER   float64 // maximum QBER error correction can handle
	PAEfficiency     float64 // privacy-amplification efficiency factor in (0,1]
	LeakageMargin    int     // extra bits sacrificed to bound leaked information
}

// DefaultParams returns standard simulation parameters.
func DefaultParams() Params {
	return Params{
		PulseCount:       4000,
		EstimateFraction: 0.2,
		QBERThreshold:    0.11,
		NoiseConfidenceZ: 4.0,
		MinSifted:        64,
		CorrectableBER:   0.11,
		PAEfficiency:     0.9,
		LeakageMargin:    16,
	}
}

// Validate checks parameter ranges.
func (p Params) Validate() error {
	switch {
	case p.PulseCount < 8:
		return errors.New("PulseCount too small")
	case p.EstimateFraction <= 0 || p.EstimateFraction >= 1:
		return errors.New("EstimateFraction must be in (0,1)")
	case p.QBERThreshold <= 0 || p.QBERThreshold >= 1:
		return errors.New("QBERThreshold must be in (0,1)")
	case p.NoiseConfidenceZ <= 0:
		return errors.New("NoiseConfidenceZ must be positive")
	case p.MinSifted < 1:
		return errors.New("MinSifted must be positive")
	case p.CorrectableBER <= 0 || p.CorrectableBER >= 1:
		return errors.New("CorrectableBER must be in (0,1)")
	case p.PAEfficiency <= 0 || p.PAEfficiency > 1:
		return errors.New("PAEfficiency must be in (0,1]")
	case p.LeakageMargin < 0:
		return errors.New("LeakageMargin must be non-negative")
	}
	return nil
}

// validateChannel checks physical parameter ranges.
func validateChannel(c quantum.ChannelParams) error {
	switch {
	case c.Transmission <= 0 || c.Transmission > 1:
		return errors.New("Transmission must be in (0,1]")
	case c.DetectorEfficiency <= 0 || c.DetectorEfficiency > 1:
		return errors.New("DetectorEfficiency must be in (0,1]")
	case c.DarkCountRate < 0 || c.DarkCountRate >= 1:
		return errors.New("DarkCountRate must be in [0,1)")
	case c.OpticalBER < 0 || c.OpticalBER >= 1:
		return errors.New("OpticalBER must be in [0,1)")
	}
	return nil
}

// RoundResult summarizes one QKD round.
type RoundResult struct {
	Accepted          bool
	Reason            RejectReason
	Seed              int64
	Sent              int
	Detected          int
	SiftedBits        int
	EstimateBits      int
	ObservedQBER      float64
	ExpectedNoiseQBER float64
	NoiseUpperBound   float64
	EveEstimate       float64
	CorrectedErrors   int
	LeakageBits       int
	FinalKeyBits      int
	LinkKey           []byte
}

func reject(seed int64, sent int, reason RejectReason) RoundResult {
	return RoundResult{Accepted: false, Reason: reason, Seed: seed, Sent: sent}
}

// Run executes one point-to-point QKD round.
func Run(rng *random.Source, seed int64, cp quantum.ChannelParams, pp Params, det *quantum.DetectorState) RoundResult {
	if err := pp.Validate(); err != nil {
		return reject(seed, 0, ReasonInvalidParams)
	}
	if err := validateChannel(cp); err != nil {
		return reject(seed, pp.PulseCount, ReasonInvalidParams)
	}

	// 1. Emission and receiver basis choice.
	photons, txBase := quantum.Emit(rng.Derive("emit"), pp.PulseCount)
	rxBase := make([]quantum.Basis, pp.PulseCount)
	for i := range rxBase {
		rxBase[i] = quantum.Basis(rng.Intn(2))
	}

	// 2. Channel transit and detection.
	events := quantum.Transit(rng.Derive("channel"), photons, rxBase, cp, det)

	// 3. Sifting: keep clicks where sender and receiver bases matched.
	var sifted []quantum.Bit
	detected := 0
	for _, ev := range events {
		if !ev.Clicked {
			continue
		}
		detected++
		if txBase[ev.Index] == rxBase[ev.Index] {
			sifted = append(sifted, ev.Bit)
		}
	}
	if len(sifted) < pp.MinSifted {
		return reject(seed, pp.PulseCount, ReasonInsufficientBits)
	}

	// 4. Deterministically split off estimation bits.
	nEst := int(math.Round(float64(len(sifted)) * pp.EstimateFraction))
	if nEst < 1 {
		nEst = 1
	}
	if nEst >= len(sifted) {
		return reject(seed, pp.PulseCount, ReasonInsufficientBits)
	}
	keyBits := sifted[nEst:]

	// 5. QBER estimation: compare received estimation bits with the true
	// sender bits in matched-basis sift order.
	sentMatches := matchedSenderBits(photons, txBase, rxBase, events)
	errs := 0
	for i := 0; i < nEst; i++ {
		if sifted[i] != sentMatches[i] {
			errs++
		}
	}
	qber := float64(errs) / float64(nEst)

	// Expected natural QBER: dark counts are random in the matched basis
	// (50% wrong); optical misalignment flips matched-basis signal bits.
	clickProb := cp.Transmission*cp.DetectorEfficiency + cp.DarkCountRate -
		cp.Transmission*cp.DetectorEfficiency*cp.DarkCountRate
	signalFraction := 0.0
	if clickProb > 0 {
		signalFraction = cp.Transmission * cp.DetectorEfficiency / clickProb
	}
	darkFraction := 1.0 - signalFraction
	expected := signalFraction*cp.OpticalBER + darkFraction*0.5

	// Statistical upper bound on the purely-natural error rate.
	stderr := math.Sqrt(expected * (1.0 - expected) / float64(nEst))
	upper := expected + pp.NoiseConfidenceZ*stderr
	if upper > 1 {
		upper = 1
	}
	eveEst := qber - expected
	if eveEst < 0 {
		eveEst = 0
	}

	// 6. Decision: eavesdropping vs. natural noise vs. accepted.
	res := RoundResult{
		Accepted:          true,
		Seed:              seed,
		Sent:              pp.PulseCount,
		Detected:          detected,
		SiftedBits:        len(sifted),
		EstimateBits:      nEst,
		ObservedQBER:      qber,
		ExpectedNoiseQBER: expected,
		NoiseUpperBound:   upper,
		EveEstimate:       eveEst,
	}

	// A real intercept-resend attack on the pulse stream is known to the
	// model and is reported explicitly; statistically, it also pushes QBER
	// beyond the natural-noise envelope.
	if cp.EveIntercept || qber > upper {
		res.Accepted = false
		res.Reason = ReasonEavesdropping
		return res
	}
	if qber > pp.QBERThreshold {
		res.Accepted = false
		res.Reason = ReasonQBERThreshold
		return res
	}

	// 7. Error correction (only reached for accepted rounds).
	rxKey := bitsToBytes(keyBits)
	txKey := bitsToBytes(sentMatches[nEst:])
	ec := reconcile(txKey, rxKey, pp.CorrectableBER)
	if ec.Failed {
		res.Accepted = false
		res.Reason = ReasonQBERThreshold
		res.CorrectedErrors = ec.ErrorCount
		return res
	}
	res.CorrectedErrors = ec.ErrorCount
	res.LeakageBits = ec.LeakageBits

	// 8. Privacy amplification; key length may never grow and is never negative.
	outLen := int(float64(len(ec.Corrected))*pp.PAEfficiency) - ec.LeakageBits - pp.LeakageMargin
	if outLen <= 0 {
		res.Accepted = false
		res.Reason = ReasonNonPositiveKey
		return res
	}
	final := privacyAmplification(ec.Corrected, outLen)
	res.FinalKeyBits = len(final)
	res.LinkKey = final
	return res
}

// matchedSenderBits returns the true sender bits in matched-basis sift order.
func matchedSenderBits(photons []quantum.Photon, txBase, rxBase []quantum.Basis, events []quantum.DetectorEvent) []quantum.Bit {
	var out []quantum.Bit
	for _, ev := range events {
		if ev.Clicked && txBase[ev.Index] == rxBase[ev.Index] {
			out = append(out, photons[ev.Index].Bit)
		}
	}
	return out
}

// bitsToBytes maps bits (0/1) 1:1 to bytes.
func bitsToBytes(bits []quantum.Bit) []byte {
	out := make([]byte, len(bits))
	for i, b := range bits {
		out[i] = byte(b)
	}
	return out
}

// String renders the key decision data for test/diagnostic logs.
func (r RoundResult) String() string {
	if !r.Accepted {
		return fmt.Sprintf("seed=%d REJECT reason=%s sent=%d detected=%d sifted=%d est=%d qber=%.4f expected=%.4f upper=%.4f eve=%.4f",
			r.Seed, r.Reason, r.Sent, r.Detected, r.SiftedBits, r.EstimateBits,
			r.ObservedQBER, r.ExpectedNoiseQBER, r.NoiseUpperBound, r.EveEstimate)
	}
	return fmt.Sprintf("seed=%d ACCEPT sent=%d detected=%d sifted=%d est=%d qber=%.4f expected=%.4f upper=%.4f corrected=%d leak=%d keybits=%d",
		r.Seed, r.Sent, r.Detected, r.SiftedBits, r.EstimateBits,
		r.ObservedQBER, r.ExpectedNoiseQBER, r.NoiseUpperBound,
		r.CorrectedErrors, r.LeakageBits, r.FinalKeyBits)
}
