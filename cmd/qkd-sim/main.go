// Command qkd-sim runs a local, self-contained QKD multi-hop relay
// simulation. It needs no network, external services or credentials.
//
// Usage:
//
//	qkd-sim [-seed N] [-hops N] [-eve HOP] [-noise P]
//
// It prints the random seed, key parameters, per-link QBER decision
// evidence and the final end-to-end key (or the explicit failure reason).
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/highcumontoa/qkd-network-simulator-go/internal/protocol"
	"github.com/highcumontoa/qkd-network-simulator-go/internal/quantum"
	"github.com/highcumontoa/qkd-network-simulator-go/internal/random"
	"github.com/highcumontoa/qkd-network-simulator-go/internal/relay"
)

func main() {
	seed := flag.Int64("seed", 20260925, "master random seed (reproducible)")
	hops := flag.Int("hops", 3, "number of links (>=1)")
	eve := flag.Int("eve", -1, "hop index carrying an intercept-resend eavesdropper (-1 = none)")
	noise := flag.Float64("noise", 0.02, "baseline optical BER per link")
	flag.Parse()

	if *hops < 1 {
		fmt.Fprintln(os.Stderr, "hops must be >= 1")
		os.Exit(2)
	}

	nodes := nodeNames(*hops)
	links := make([]relay.LinkSpec, *hops)
	for i := 0; i < *hops; i++ {
		ch := quantum.ChannelParams{
			Transmission:       0.9,
			DetectorEfficiency: 0.9,
			DarkCountRate:      1e-4,
			OpticalBER:         *noise,
			EveIntercept:       i == *eve,
		}
		links[i] = relay.LinkSpec{
			From: nodes[i], To: nodes[i+1], Channel: ch, Trusted: true,
		}
	}
	spec := relay.PathSpec{
		Sender:   nodes[0],
		Receiver: nodes[len(nodes)-1],
		Relays:   nodes[1 : len(nodes)-1],
		Links:    links,
	}
	opts := relay.DefaultOptions(*seed)

	fmt.Printf("=== QKD multi-hop simulation ===\n")
	fmt.Printf("seed=%d hops=%d eveHop=%d opticalBER=%.3f\n",
		*seed, *hops, *eve, *noise)
	pp := opts.Protocol
	fmt.Printf("params: pulses=%d estFraction=%.2f qberThreshold=%.3f z=%.1f minSifted=%d paEff=%.2f\n",
		pp.PulseCount, pp.EstimateFraction, pp.QBERThreshold,
		pp.NoiseConfidenceZ, pp.MinSifted, pp.PAEfficiency)

	res := relay.Run(random.NewRoot(*seed), spec, opts)

	for i, h := range res.Hops {
		fmt.Printf("[hop %d %s->%s] %s\n", i, h.From, h.To, h.Round.String())
	}

	if !res.OK {
		fmt.Printf("RESULT: REJECTED path=%s reason=%s detail=%s\n",
			res.PathID, res.Reason, res.Detail)
		os.Exit(1)
	}
	fmt.Printf("RESULT: SUCCESS path=%s e2eKeyBytes=%d\n", res.PathID, res.KeyBytes)
	fmt.Printf("key=%x\n", res.Key)

	// Demonstrate point-link protocol in isolation too (single run).
	_ = protocol.DefaultParams
}

func nodeNames(hops int) []string {
	names := []string{"Alice"}
	for i := 0; i < hops-1; i++ {
		names = append(names, fmt.Sprintf("Relay%d", i+1))
	}
	names = append(names, "Bob")
	return names
}
