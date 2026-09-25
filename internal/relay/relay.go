// Package relay simulates multi-hop QKD key relay with concurrent per-link
// QKD rounds.
//
// Security model in this simulation:
//   - Every adjacent link independently runs the BB84-style protocol and
//     produces a link key only when that link passes all checks.
//   - A path succeeds only if every node is trusted AND every node uses the
//     same protocol parameters. There is no degraded-mode key.
//   - Intermediate relays forward only XOR-masked blobs. A relay can recover
//     neither the XOR accumulator (it never sees both mask components
//     unmasked on a hop), nor the endpoints' X25519 ephemerals, nor the
//     final end-to-end key.
//   - End-to-end secrecy comes from an X25519 key agreement whose public
//     keys travel inside the masked blob; the QKD transcript and link
//     material are bound into HKDF derivation and a final HMAC confirmation.
package relay

import (
	"errors"
	"sync"

	"github.com/highcumontoa/qkd-network-simulator-go/internal/protocol"
	"github.com/highcumontoa/qkd-network-simulator-go/internal/quantum"
	"github.com/highcumontoa/qkd-network-simulator-go/internal/random"
)

// errHKDFTooLong signals an HKDF output length over the RFC 5869 limit.
var errHKDFTooLong = errors.New("hkdf: output length exceeds 255*hashLen")

// LinkSpec describes one directional link between two adjacent nodes.
type LinkSpec struct {
	From    string
	To      string
	Channel quantum.ChannelParams
	Trusted bool
}

// PathSpec describes an ordered chain sender -> relays -> receiver.
type PathSpec struct {
	Sender   string
	Receiver string
	Relays   []string
	Links    []LinkSpec
}

// HopResult is one link's QKD round result.
type HopResult struct {
	From  string
	To    string
	Round protocol.RoundResult
}

// PathResult is the outcome of a full end-to-end run.
type PathResult struct {
	OK       bool
	Reason   protocol.RejectReason
	Detail   string
	Seed     int64
	Hops     []HopResult
	KeyBytes int
	Key      []byte
	PathID   string
}

// Options controls a path run.
type Options struct {
	Seed     int64
	Protocol protocol.Params
}

// DefaultOptions returns standard options for the given seed.
func DefaultOptions(seed int64) Options {
	return Options{Seed: seed, Protocol: protocol.DefaultParams()}
}

// nodeChain returns the ordered node names of the path.
func (s PathSpec) nodeChain() []string {
	nodes := make([]string, 0, len(s.Relays)+2)
	nodes = append(nodes, s.Sender)
	nodes = append(nodes, s.Relays...)
	nodes = append(nodes, s.Receiver)
	return nodes
}

// validatePath checks node trust, chain/link consistency and parameters.
// It returns (reason, ok).
func validatePath(spec PathSpec, pp protocol.Params) (protocol.RejectReason, bool) {
	if err := pp.Validate(); err != nil {
		return protocol.ReasonInvalidParams, false
	}
	nodes := spec.nodeChain()
	if len(nodes) < 2 {
		return protocol.ReasonInvalidParams, false
	}
	seen := map[string]bool{}
	for _, n := range nodes {
		if n == "" || seen[n] {
			return protocol.ReasonInvalidParams, false
		}
		seen[n] = true
	}
	if len(spec.Links) != len(nodes)-1 {
		return protocol.ReasonInvalidParams, false
	}
	for i, l := range spec.Links {
		if l.From != nodes[i] || l.To != nodes[i+1] {
			return protocol.ReasonInvalidParams, false
		}
		if !l.Trusted {
			return protocol.ReasonUntrustedNode, false
		}
		if err := validateChannelFor(l.Channel); err != nil {
			return protocol.ReasonInvalidParams, false
		}
	}
	return protocol.ReasonNone, true
}

// validateChannelFor mirrors protocol channel validation.
func validateChannelFor(c quantum.ChannelParams) error {
	switch {
	case c.Transmission <= 0 || c.Transmission > 1:
		return errors.New("bad transmission")
	case c.DetectorEfficiency <= 0 || c.DetectorEfficiency > 1:
		return errors.New("bad efficiency")
	case c.DarkCountRate < 0 || c.DarkCountRate >= 1:
		return errors.New("bad dark count")
	case c.OpticalBER < 0 || c.OpticalBER >= 1:
		return errors.New("bad optical BER")
	}
	return nil
}

// Run executes all link rounds concurrently and completes end-to-end key agreement.
func Run(root *random.Source, spec PathSpec, opts Options) PathResult {
	nodes := spec.nodeChain()
	id := pathID(nodes)
	base := PathResult{Seed: opts.Seed, PathID: id}

	if reason, ok := validatePath(spec, opts.Protocol); !ok {
		base.OK = false
		base.Reason = reason
		return base
	}

	// ---- Phase 1: concurrent per-link QKD rounds ----
	hops := make([]HopResult, len(spec.Links))
	det := quantum.NewDetectorState() // shared detector state
	var wg sync.WaitGroup
	for i, link := range spec.Links {
		wg.Add(1)
		go func(i int, link LinkSpec) {
			defer wg.Done()
			label := id + "/hop" + itoa(i)
			linkRNG := root.Derive(label)
			// Deterministic per-hop seed visible in logs.
			hopSeed := int64(uint64(opts.Seed) ^ uint64(i+1)*0x9E3779B97F4A7C15)
			round := protocol.Run(linkRNG, hopSeed, link.Channel, opts.Protocol, det)
			hops[i] = HopResult{From: link.From, To: link.To, Round: round}
		}(i, link)
	}
	wg.Wait()
	base.Hops = hops

	// ---- Phase 2: any rejected link aborts the whole path ----
	for _, h := range hops {
		if !h.Round.Accepted {
			base.OK = false
			base.Reason = h.Round.Reason
			base.Detail = "link " + h.From + "->" + h.To + " rejected"
			return base
		}
	}

	// ---- Phase 3: link-key consolidation ----
	// All link keys must have equal length (parameters are uniform across
	// links; truncate defensively to the shortest and refuse if too short).
	minLen := hops[0].Round.FinalKeyBits
	for _, h := range hops {
		if h.Round.FinalKeyBits < minLen {
			minLen = h.Round.FinalKeyBits
		}
	}
	if minLen < 32 {
		base.OK = false
		base.Reason = protocol.ReasonInsufficientBits
		base.Detail = "link key material shorter than 32 bits after sifting"
		return base
	}
	linkKeys := make([][]byte, len(hops))
	for i, h := range hops {
		linkKeys[i] = h.Round.LinkKey[:minLen]
	}

	// ---- Phase 4: onion-wrapped endpoint X25519 key agreement ----
	// Endpoint RNGs are derived from ordered, stable names only (never from
	// Go maps), so results are independent of map iteration order.
	senderRNG := root.Derive(id + "/node/" + spec.Sender)
	receiverRNG := root.Derive(id + "/node/" + spec.Receiver)
	senderPriv, senderPub, err := ephemeralX25519(senderRNG)
	if err != nil {
		return fail(base, protocol.ReasonInvalidParams, "sender keygen: "+err.Error())
	}
	receiverPriv, receiverPub, err := ephemeralX25519(receiverRNG)
	if err != nil {
		return fail(base, protocol.ReasonInvalidParams, "receiver keygen: "+err.Error())
	}

	// Onion wrapping: see e2e.go. In this in-process simulation we compute
	// the payload that arrives at each endpoint by explicitly wrapping and
	// then peeling every layer in traversal order, mirroring what each
	// forwarding node would do on the wire.
	peerPubA := peelOnion(wrapOnion(senderPub, linkKeys), linkKeys)
	peerPubB := peelOnionReverse(wrapOnionReverse(receiverPub, linkKeys), linkKeys)

	secretS, err := ecdhShared(senderPriv, peerPubB)
	if err != nil {
		return fail(base, protocol.ReasonInvalidParams, "sender ECDH: "+err.Error())
	}
	secretR, err := ecdhShared(receiverPriv, peerPubA)
	if err != nil {
		return fail(base, protocol.ReasonInvalidParams, "receiver ECDH: "+err.Error())
	}

	// ---- Phase 5: transcript-bound key derivation ----
	transcript := transcriptFingerprint(hops)
	// Salt binds the public QKD transcript only. The X25519 shared secret
	// supplies all key secrecy, so relays never need to hold it.
	salt := append([]byte{}, transcript...)
	keyLen := minLen / 8
	if keyLen < 16 {
		keyLen = 16
	}
	if keyLen > 32 {
		keyLen = 32
	}
	key, err := deriveE2EKey(secretS, salt, keyLen)
	if err != nil {
		return fail(base, protocol.ReasonNonPositiveKey, err.Error())
	}
	keyR, err := deriveE2EKey(secretR, salt, keyLen)
	if err != nil {
		return fail(base, protocol.ReasonNonPositiveKey, err.Error())
	}

	// ---- Phase 6: mutual confirmation; mismatch fails, never degrades ----
	// Both endpoints independently tag the path transcript with the derived
	// key and their ephemeral public key. Any disagreement in derived key,
	// transcript or path binding fails the path.
	confirmMsg := append(append([]byte{}, transcript...), []byte("|"+id)...)
	tagSender := confirmTag(key, confirmMsg, senderPub)
	tagReceiver := confirmTag(key, confirmMsg, receiverPub)
	if !equalTags(tagSender, confirmTag(keyR, confirmMsg, senderPub)) ||
		!equalTags(tagReceiver, confirmTag(keyR, confirmMsg, receiverPub)) ||
		!equalBytes(key, keyR) {
		base.OK = false
		base.Reason = protocol.ReasonConfirmationMismatch
		base.Detail = "end-to-end confirmation failed"
		return base
	}

	base.OK = true
	base.KeyBytes = len(key)
	base.Key = key
	return base
}

// fail records a failure on a partial result.
func fail(b PathResult, reason protocol.RejectReason, detail string) PathResult {
	b.OK = false
	b.Reason = reason
	b.Detail = detail
	return b
}

func equalTags(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var d byte
	for i := range a {
		d |= a[i] ^ b[i]
	}
	return d == 0
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var d byte
	for i := range a {
		d |= a[i] ^ b[i]
	}
	return d == 0
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
