package protocol

import (
	"testing"

	"github.com/highcumontoa/qkd-network-simulator-go/internal/quantum"
	"github.com/highcumontoa/qkd-network-simulator-go/internal/random"
)

func goodChannel() quantum.ChannelParams {
	return quantum.ChannelParams{
		Transmission:       0.9,
		DetectorEfficiency: 0.9,
		DarkCountRate:      1e-4,
		OpticalBER:         0.02,
	}
}

// TestReproducible verifies identical seeds yield identical round results.
func TestReproducible(t *testing.T) {
	pp := DefaultParams()
	cp := goodChannel()
	r1 := Run(random.NewRoot(42), 42, cp, pp, quantum.NewDetectorState())
	r2 := Run(random.NewRoot(42), 42, cp, pp, quantum.NewDetectorState())
	t.Logf("seed=42 params=%+v", pp)
	t.Logf("run1: %s", r1.String())
	t.Logf("run2: %s", r2.String())
	if !r1.Accepted || !r2.Accepted {
		t.Fatalf("good channel should be accepted")
	}
	if r1.FinalKeyBits != r2.FinalKeyBits {
		t.Fatalf("key lengths differ: %d vs %d", r1.FinalKeyBits, r2.FinalKeyBits)
	}
	if string(r1.LinkKey) != string(r2.LinkKey) {
		t.Fatal("link keys differ under same seed")
	}
	if r1.ObservedQBER != r2.ObservedQBER || r1.SiftedBits != r2.SiftedBits {
		t.Fatal("statistics differ under same seed")
	}
}

// TestNoiseVsEavesdropping verifies the two error sources get distinct
// decision reasons across many seeds.
func TestNoiseVsEavesdropping(t *testing.T) {
	pp := DefaultParams()
	var noiseRejects, eveRejects, accepts int
	for seed := int64(1); seed <= 12; seed++ {
		// High natural optical noise, no eavesdropper.
		noiseCP := goodChannel()
		noiseCP.OpticalBER = 0.20
		rn := Run(random.NewRoot(seed), seed, noiseCP, pp, quantum.NewDetectorState())
		t.Logf("[noise seed=%d] %s", seed, rn.String())
		if rn.Accepted {
			t.Fatalf("seed %d: high natural noise must not be accepted", seed)
		}
		if rn.Reason == ReasonEavesdropping {
			t.Fatalf("seed %d: pure natural noise misclassified as eavesdropping (qber=%.3f upper=%.3f)",
				seed, rn.ObservedQBER, rn.NoiseUpperBound)
		}
		if rn.Reason == ReasonQBERThreshold {
			noiseRejects++
		}

		// Intercept-resend eavesdropper at low optical noise.
		eveCP := goodChannel()
		eveCP.EveIntercept = true
		re := Run(random.NewRoot(seed+1000), seed+1000, eveCP, pp, quantum.NewDetectorState())
		t.Logf("[eve   seed=%d] %s", seed+1000, re.String())
		if re.Accepted || re.Reason != ReasonEavesdropping {
			t.Fatalf("seed %d: eavesdropping must be classified as %s, got accepted=%v reason=%s",
				seed, ReasonEavesdropping, re.Accepted, re.Reason)
		}
		eveRejects++
		if len(re.LinkKey) != 0 {
			t.Fatal("rejected eavesdropping round must carry no key material")
		}
	}
	clean := Run(random.NewRoot(2000), 2000, goodChannel(), pp, quantum.NewDetectorState())
	if clean.Accepted {
		accepts++
	}
	t.Logf("summary: naturalQBERrejects=%d eavesdropRejects=%d cleanAccepts=%d",
		noiseRejects, eveRejects, accepts)
	if noiseRejects == 0 || accepts == 0 {
		t.Fatal("expected at least one natural-noise rejection and one clean accept")
	}
}

// TestRejectedRoundsCarryNoKeyMaterial enforces the security gate.
func TestRejectedRoundsCarryNoKeyMaterial(t *testing.T) {
	pp := DefaultParams()

	// Almost-total loss -> insufficient sifted bits.
	lossCP := goodChannel()
	lossCP.Transmission = 1e-6
	rl := Run(random.NewRoot(1), 1, lossCP, pp, quantum.NewDetectorState())
	t.Logf("[loss] %s", rl.String())
	if rl.Accepted || rl.Reason != ReasonInsufficientBits {
		t.Fatalf("expected %s, got %v/%s", ReasonInsufficientBits, rl.Accepted, rl.Reason)
	}
	if rl.LinkKey != nil {
		t.Fatal("insufficient-bits round must not carry key")
	}

	// Eve round.
	eveCP := goodChannel()
	eveCP.EveIntercept = true
	re := Run(random.NewRoot(2), 2, eveCP, pp, quantum.NewDetectorState())
	if re.LinkKey != nil || re.FinalKeyBits != 0 {
		t.Fatal("eavesdropped round must not carry key")
	}
}

// TestKeyLengthNeverNegativeOrInflated checks length accounting.
func TestKeyLengthNeverNegativeOrInflated(t *testing.T) {
	pp := DefaultParams()
	for seed := int64(0); seed < 10; seed++ {
		r := Run(random.NewRoot(seed), seed, goodChannel(), pp, quantum.NewDetectorState())
		if !r.Accepted {
			t.Logf("seed=%d rejected: %s (allowed)", seed, r.String())
			if r.FinalKeyBits < 0 || r.LinkKey != nil {
				t.Fatal("rejected round has negative key bits or non-nil key")
			}
			continue
		}
		remaining := r.SiftedBits - r.EstimateBits
		// PA output cannot exceed the reconciled key minus leakage/margin.
		maxAllowed := int(float64(remaining)*pp.PAEfficiency) - r.LeakageBits - pp.LeakageMargin
		if r.FinalKeyBits <= 0 || r.FinalKeyBits > maxAllowed {
			t.Fatalf("seed=%d key bits %d out of sane range (remaining=%d leak=%d max=%d)",
				seed, r.FinalKeyBits, remaining, r.LeakageBits, maxAllowed)
		}
		if len(r.LinkKey) != r.FinalKeyBits {
			t.Fatalf("key slice length %d != reported %d", len(r.LinkKey), r.FinalKeyBits)
		}
		t.Logf("seed=%d sifted=%d est=%d leak=%d final=%d (<= %d)",
			seed, r.SiftedBits, r.EstimateBits, r.LeakageBits, r.FinalKeyBits, maxAllowed)
	}
}

// TestParameterBoundaries covers invalid and boundary parameters.
func TestParameterBoundaries(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Params)
		chanFn func(*quantum.ChannelParams)
	}{
		{"bad transmission", func(p *Params) {}, func(c *quantum.ChannelParams) { c.Transmission = 1.5 }},
		{"bad efficiency", func(p *Params) {}, func(c *quantum.ChannelParams) { c.DetectorEfficiency = 0 }},
		{"bad dark rate", func(p *Params) {}, func(c *quantum.ChannelParams) { c.DarkCountRate = 1 }},
		{"bad optical ber", func(p *Params) {}, func(c *quantum.ChannelParams) { c.OpticalBER = 1 }},
		{"zero pulses", func(p *Params) { p.PulseCount = 0 }, func(c *quantum.ChannelParams) {}},
		{"bad est fraction", func(p *Params) { p.EstimateFraction = 1 }, func(c *quantum.ChannelParams) {}},
		{"bad threshold", func(p *Params) { p.QBERThreshold = 2 }, func(c *quantum.ChannelParams) {}},
		{"bad z", func(p *Params) { p.NoiseConfidenceZ = 0 }, func(c *quantum.ChannelParams) {}},
		{"bad pa eff", func(p *Params) { p.PAEfficiency = 0 }, func(c *quantum.ChannelParams) {}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pp := DefaultParams()
			tc.mutate(&pp)
			c := goodChannel()
			tc.chanFn(&c)
			r := Run(random.NewRoot(9), 9, c, pp, quantum.NewDetectorState())
			t.Logf("[%s] %s", tc.name, r.String())
			if r.Accepted || r.Reason != ReasonInvalidParams {
				t.Fatalf("%s: expected invalid_parameters rejection, got accepted=%v reason=%s",
					tc.name, r.Accepted, r.Reason)
			}
			if r.LinkKey != nil {
				t.Fatal("invalid-parameter round must carry no key")
			}
		})
	}
}

// TestChannelLossAndDarkCountsAffectKey verifies physical parameters move
// the detected/sifted counts and final key in the expected direction.
func TestChannelLossAndDarkCountsAffectKey(t *testing.T) {
	pp := DefaultParams()
	high := Run(random.NewRoot(55), 55, goodChannel(), pp, quantum.NewDetectorState())
	lowCP := goodChannel()
	lowCP.Transmission = 0.5
	lowCP.DetectorEfficiency = 0.6
	low := Run(random.NewRoot(55), 55, lowCP, pp, quantum.NewDetectorState())
	t.Logf("[high eff] %s", high.String())
	t.Logf("[low  eff] %s", low.String())
	if !high.Accepted || !low.Accepted {
		t.Fatal("both should pass at these levels")
	}
	if low.Detected >= high.Detected {
		t.Fatalf("lower transmission/efficiency must yield fewer detections (%d vs %d)",
			low.Detected, high.Detected)
	}
	if low.FinalKeyBits >= high.FinalKeyBits {
		t.Fatal("lossier channel must not yield a longer key")
	}
}

// TestDarkCountsRaiseNoise verifies dark counts inflate the expected natural
// QBER floor (random detectors in the matched basis err ~50%).
func TestDarkCountsRaiseNoiseFloor(t *testing.T) {
	pp := DefaultParams()
	cp := goodChannel()
	r1 := Run(random.NewRoot(70), 70, cp, pp, quantum.NewDetectorState())
	cp.DarkCountRate = 0.05
	r2 := Run(random.NewRoot(70), 70, cp, pp, quantum.NewDetectorState())
	t.Logf("[low dark] expectedQBER=%.4f", r1.ExpectedNoiseQBER)
	t.Logf("[high dark] expectedQBER=%.4f", r2.ExpectedNoiseQBER)
	if r2.ExpectedNoiseQBER <= r1.ExpectedNoiseQBER {
		t.Fatal("higher dark count rate must raise expected natural QBER floor")
	}
}
