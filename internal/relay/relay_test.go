package relay

import (
	"bytes"
	"sync"
	"testing"

	"github.com/highcumontoa/qkd-network-simulator-go/internal/protocol"
	"github.com/highcumontoa/qkd-network-simulator-go/internal/quantum"
	"github.com/highcumontoa/qkd-network-simulator-go/internal/random"
)

func goodChan() quantum.ChannelParams {
	return quantum.ChannelParams{
		Transmission:       0.9,
		DetectorEfficiency: 0.9,
		DarkCountRate:      1e-4,
		OpticalBER:         0.02,
	}
}

func chain(names []string, mut func(i int, c *quantum.ChannelParams), trusted []bool) PathSpec {
	links := make([]LinkSpec, len(names)-1)
	for i := 0; i < len(names)-1; i++ {
		c := goodChan()
		if mut != nil {
			mut(i, &c)
		}
		t := true
		if trusted != nil {
			t = trusted[i]
		}
		links[i] = LinkSpec{From: names[i], To: names[i+1], Channel: c, Trusted: t}
	}
	relays := []string{}
	if len(names) > 2 {
		relays = names[1 : len(names)-1]
	}
	return PathSpec{Sender: names[0], Receiver: names[len(names)-1], Relays: relays, Links: links}
}

func names3() []string { return []string{"A", "R1", "R2", "B"} }

// TestCleanPathSucceeds is the happy path.
func TestCleanPathSucceeds(t *testing.T) {
	r := Run(random.NewRoot(7), chain(names3(), nil, nil), DefaultOptions(7))
	t.Logf("seed=7 path=%s ok=%v keyBytes=%d", r.PathID, r.OK, r.KeyBytes)
	for _, h := range r.Hops {
		t.Logf("  %s", h.Round.String())
	}
	if !r.OK {
		t.Fatalf("clean path failed: %s %s", r.Reason, r.Detail)
	}
	if r.KeyBytes != 32 {
		t.Fatalf("expected 32-byte e2e key, got %d", r.KeyBytes)
	}
}

// TestReproducibleEndToEnd verifies bit-exact key reproducibility.
func TestReproducibleEndToEnd(t *testing.T) {
	for _, seed := range []int64{1, 42, 999999} {
		r1 := Run(random.NewRoot(seed), chain(names3(), nil, nil), DefaultOptions(seed))
		r2 := Run(random.NewRoot(seed), chain(names3(), nil, nil), DefaultOptions(seed))
		if !r1.OK || !r2.OK {
			t.Fatalf("seed %d path failed", seed)
		}
		if !bytes.Equal(r1.Key, r2.Key) {
			t.Fatalf("seed %d e2e keys differ", seed)
		}
		t.Logf("seed=%d e2e key reproducible (%d bytes) hops=%d", seed, r1.KeyBytes, len(r1.Hops))
	}
}

// TestSingleHopAlsoWorks covers the direct sender->receiver case.
func TestSingleHopAlsoWorks(t *testing.T) {
	spec := chain([]string{"A", "B"}, nil, nil)
	r := Run(random.NewRoot(3), spec, DefaultOptions(3))
	t.Logf("single-hop: ok=%v reason=%s keyBytes=%d", r.OK, r.Reason, r.KeyBytes)
	if !r.OK {
		t.Fatalf("single hop failed: %s %s", r.Reason, r.Detail)
	}
}

// TestEavesdropperOnAnyHopRejectsPath verifies rejection propagation and
// distinct reason, plus no e2e key material on failure.
func TestEavesdropperOnAnyHopRejectsPath(t *testing.T) {
	for eveAt := 0; eveAt < 3; eveAt++ {
		spec := chain(names3(), func(i int, c *quantum.ChannelParams) {
			if i == eveAt {
				c.EveIntercept = true
			}
		}, nil)
		r := Run(random.NewRoot(11), spec, DefaultOptions(11))
		t.Logf("eveAt=%d ok=%v reason=%s detail=%s", eveAt, r.OK, r.Reason, r.Detail)
		if r.OK || r.Reason != protocol.ReasonEavesdropping {
			t.Fatalf("eve at hop %d must reject as eavesdropping, got ok=%v %s", eveAt, r.OK, r.Reason)
		}
		if r.Key != nil {
			t.Fatal("rejected path must not return an e2e key")
		}
	}
}

// TestNaturalNoiseRejectsDistinctReason verifies noise vs eve distinction on paths.
func TestNaturalNoiseRejectsDistinctReason(t *testing.T) {
	spec := chain(names3(), func(i int, c *quantum.ChannelParams) {
		c.OpticalBER = 0.22
	}, nil)
	r := Run(random.NewRoot(12), spec, DefaultOptions(12))
	t.Logf("noise path: ok=%v reason=%s detail=%s", r.OK, r.Reason, r.Detail)
	if r.OK {
		t.Fatal("noisy path must not succeed")
	}
	if r.Reason == protocol.ReasonEavesdropping {
		t.Fatal("natural noise must not be classified as eavesdropping")
	}
	if r.Reason != protocol.ReasonQBERThreshold {
		t.Fatalf("expected natural QBER rejection, got %s", r.Reason)
	}
}

// TestUntrustedNodeFailsExplicitly verifies the trust gate.
func TestUntrustedNodeFailsExplicitly(t *testing.T) {
	spec := chain(names3(), nil, []bool{true, false, true})
	r := Run(random.NewRoot(5), spec, DefaultOptions(5))
	t.Logf("untrusted: ok=%v reason=%s", r.OK, r.Reason)
	if r.OK || r.Reason != protocol.ReasonUntrustedNode {
		t.Fatalf("expected untrusted_node, got ok=%v %s", r.OK, r.Reason)
	}
}

// TestParameterMismatchFails verifies a path cannot run with inconsistent
// parameters: here a malformed spec (link endpoints not matching chain)
// and an invalid options set must fail explicitly rather than degrade.
func TestParameterMismatchFails(t *testing.T) {
	// Broken chain wiring.
	good := chain(names3(), nil, nil)
	bad := good
	bad.Links[1].To = "Ghost"
	r := Run(random.NewRoot(8), bad, DefaultOptions(8))
	t.Logf("broken chain: ok=%v reason=%s", r.OK, r.Reason)
	if r.OK || r.Reason != protocol.ReasonInvalidParams {
		t.Fatal("broken chain must fail as invalid_parameters")
	}
	// Invalid protocol params.
	opts := DefaultOptions(8)
	opts.Protocol.QBERThreshold = 5
	r2 := Run(random.NewRoot(8), good, opts)
	if r2.OK || r2.Reason != protocol.ReasonInvalidParams {
		t.Fatal("invalid protocol params must fail explicitly")
	}
}

// TestConcurrentPaths verifies many paths run in parallel from a shared
// root source with no data race and independently reproducible results.
func TestConcurrentPaths(t *testing.T) {
	const n = 24
	// Serial reference keys for each (seed, eveAt) combination.
	refs := make(map[int64][]byte)
	for i := 0; i < n; i++ {
		seed := int64(100 + i)
		r := Run(random.NewRoot(seed), chain(names3(), nil, nil), DefaultOptions(seed))
		if !r.OK {
			t.Fatalf("serial seed %d failed", seed)
		}
		refs[seed] = r.Key
	}
	// Concurrent re-runs from fresh roots sharing nothing but construction.
	errCh := make(chan string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			seed := int64(100 + i)
			r := Run(random.NewRoot(seed), chain(names3(), nil, nil), DefaultOptions(seed))
			if !r.OK || !bytes.Equal(r.Key, refs[seed]) {
				errCh <- "concurrent run diverged"
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for e := range errCh {
		t.Fatal(e)
	}
	t.Logf("seed-base=100 concurrentPaths=%d all keys match serial reference", n)
}

// TestConcurrentMixedOutcomes runs clean, noisy and eavesdropped paths
// concurrently and verifies each lands in the expected decision bucket.
func TestConcurrentMixedOutcomes(t *testing.T) {
	const perKind = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	var got []protocol.RejectReason
	run := func(seed int64, spec PathSpec) {
		defer wg.Done()
		r := Run(random.NewRoot(seed), spec, DefaultOptions(seed))
		if !r.OK {
			mu.Lock()
			got = append(got, r.Reason)
			mu.Unlock()
		}
	}
	for i := 0; i < perKind; i++ {
		wg.Add(3)
		seed := int64(500 + i)
		go run(seed, chain(names3(), nil, nil))
		go run(seed+1000, chain(names3(), func(i int, c *quantum.ChannelParams) {
			if i == 0 {
				c.EveIntercept = true
			}
		}, nil))
		go run(seed+2000, chain(names3(), func(i int, c *quantum.ChannelParams) {
			c.OpticalBER = 0.25
		}, nil))
	}
	wg.Wait()
	var eve, noise int
	for _, rs := range got {
		switch rs {
		case protocol.ReasonEavesdropping:
			eve++
		case protocol.ReasonQBERThreshold:
			noise++
		default:
			t.Fatalf("unexpected rejection reason: %s", rs)
		}
	}
	t.Logf("concurrent mixed outcomes: eavesdrop=%d noise=%d (expect %d each)", eve, noise, perKind)
	if eve != perKind || noise != perKind {
		t.Fatalf("expected %d/%d eve/noise rejections, got %d/%d", perKind, perKind, eve, noise)
	}
}

// TestRelayCannotSeeEndToEndKey is a structural security assertion: every
// intermediate node's observable onion blob is distinct from the endpoint
// ephemeral payload and blinded; the payload is only recreated at an endpoint.
func TestRelayCannotSeeEndToEndKey(t *testing.T) {
	keys := make([][]byte, 3)
	for i := range keys {
		rng := random.NewRoot(int64(100 + i)).Derive("linkkey")
		k := make([]byte, 32)
		rng.Read(k)
		keys[i] = k
	}
	payload := make([]byte, 32)
	random.NewRoot(4242).Derive("ephemeral").Read(payload)

	views := relayViews(payload, keys)
	if len(views) != 2 {
		t.Fatalf("expected 2 relay views, got %d", len(views))
	}
	// No relay ever sees the raw payload on the wire.
	for i, v := range views {
		if bytes.Equal(v, payload) {
			t.Fatalf("relay %d saw the unmasked endpoint payload", i)
		}
	}
	// Interior relay R1 (view 0) holds only K0,K1; with either key it must
	// not be able to recover the payload (K2 is still unknown to it).
	for _, j := range []int{0, 1} {
		if bytes.Equal(xorBytes(views[0], keys[j]), payload) {
			t.Fatalf("interior relay unmasked payload with adjacent key %d", j)
		}
	}
	// The last relay is the receiver's adjacent trusted node: it forwards
	// P XOR K2, which only the receiver unmasks. The forwarded blob itself
	// is still blinded and is never the endpoint shared secret or private key.
	if !bytes.Equal(xorBytes(views[1], keys[2]), payload) {
		t.Fatal("receiver should recover payload by peeling the final key")
	}
	if got := peelOnion(wrapOnion(payload, keys), keys); !bytes.Equal(got, payload) {
		t.Fatal("sender->receiver onion did not recover payload")
	}
	if got := peelOnionReverse(wrapOnionReverse(payload, keys), keys); !bytes.Equal(got, payload) {
		t.Fatal("receiver->sender onion did not recover payload")
	}
	t.Log("onion blobs at both relays never expose the endpoint payload; both directions peel correctly")
}
