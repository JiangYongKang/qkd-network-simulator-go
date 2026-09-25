package protocol

import (
	"math"
)

// ecResult is the output of error correction simulation.
type ecResult struct {
	Corrected   []byte // bits as bytes (0/1), converged to the sender's bits
	ErrorCount  int
	LeakageBits int
	Failed      bool // error rate exceeded the code's correctable capacity
}

// binaryEntropy h2(p) in bits.
func binaryEntropy(p float64) float64 {
	if p <= 0 || p >= 1 {
		return 0
	}
	return -p*math.Log2(p) - (1-p)*math.Log2(1-p)
}

// reconcile simulates one-way information reconciliation (CASCADE-style
// parity exchange) on the key portion. tx are the sender bits, rx the
// receiver bits, each stored as a byte with value 0 or 1.
//
// It never invents bits: the corrected key has exactly the length of the
// input and converges to the sender view. LeakageBits is the information
// exposed through parity messages, modeled as n*h2(qber) plus a fixed block
// framing term, rounded up.
func reconcile(tx, rx []byte, correctableBER float64) ecResult {
	n := len(tx)
	errs := 0
	for i := 0; i < n; i++ {
		if tx[i] != rx[i] {
			errs++
		}
	}
	rate := float64(errs) / float64(n)
	if rate > correctableBER {
		return ecResult{Failed: true, ErrorCount: errs}
	}
	out := make([]byte, n)
	copy(out, tx) // receiver converges to sender's post-correction view
	leak := int(math.Ceil(float64(n)*binaryEntropy(rate))) + 8
	if leak > n {
		leak = n
	}
	return ecResult{Corrected: out, ErrorCount: errs, LeakageBits: leak}
}

// privacyAmplification applies a deterministic Toeplitz-matrix extractor
// over GF(2). Input bits are bytes with value 0/1; output is outBits bits
// in the same representation, each a parity over an LFSR-generated row.
// outBits must be <= len(key); the function never increases key length.
func privacyAmplification(key []byte, outBits int) []byte {
	n := len(key)
	if outBits <= 0 {
		return nil
	}
	if outBits > n {
		outBits = n
	}
	// Deterministic LFSR (x^31 + x^6 + 1) fills the Toeplitz diagonal
	// sequence of length n+outBits-1.
	total := n + outBits - 1
	seq := make([]byte, total)
	reg := uint32(0x12345678)
	for i := range seq {
		seq[i] = byte(reg & 1)
		bit := (reg >> 30) ^ ((reg >> 5) & 1)
		reg = (reg << 1) | (bit & 1)
	}
	out := make([]byte, outBits)
	for i := 0; i < outBits; i++ {
		var parity byte
		for j := 0; j < n; j++ {
			if seq[i+j] == 1 {
				parity ^= key[j]
			}
		}
		out[i] = parity & 1
	}
	return out
}
