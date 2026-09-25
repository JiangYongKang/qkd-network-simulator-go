package relay

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math"

	"github.com/highcumontoa/qkd-network-simulator-go/internal/random"
)

// xorBytes returns a XOR b; the result length is len(a). b is cyclically
// repeated (callers normally pass equal-length slices).
func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range out {
		out[i] = a[i] ^ b[i%len(b)]
	}
	return out
}

// wrapOnion builds a sender->receiver onion around payload:
//
//	payload XOR K0 XOR K1 XOR ... XOR Km
//
// where K0 is the first-hop link key and Km the last-hop key held by the
// receiver. Wrapping starts from the innermost (last hop) layer so that each
// forwarder only has to peel its own layer.
func wrapOnion(payload []byte, keys [][]byte) []byte {
	out := append([]byte{}, payload...)
	for i := len(keys) - 1; i >= 0; i-- {
		out = xorBytes(out, keys[i])
	}
	return out
}

// peelOnion advances an onion across hops in traversal order: node on hop i
// removes exactly its own link key. After all hops the receiver gets the
// payload. Each intermediate view is the payload XOR-masked by at least one
// key that node does not hold (for paths of 3+ links).
func peelOnion(onion []byte, keys [][]byte) []byte {
	out := append([]byte{}, onion...)
	for i := 0; i < len(keys); i++ {
		out = xorBytes(out, keys[i])
	}
	return out
}

// wrapOnionReverse builds the receiver->sender onion (traversal order is the
// reverse, but layers peel with the same keys).
func wrapOnionReverse(payload []byte, keys [][]byte) []byte {
	out := append([]byte{}, payload...)
	for i := 0; i < len(keys); i++ {
		out = xorBytes(out, keys[i])
	}
	return out
}

// peelOnionReverse advances a receiver->sender onion back to the sender.
func peelOnionReverse(onion []byte, keys [][]byte) []byte {
	out := append([]byte{}, onion...)
	for i := len(keys) - 1; i >= 0; i-- {
		out = xorBytes(out, keys[i])
	}
	return out
}

// relayViews returns every intermediate node's observable blob while an
// onion travels sender->receiver. Used to assert that no single view equals
// the payload on a path with at least 3 links.
func relayViews(payload []byte, keys [][]byte) [][]byte {
	views := make([][]byte, 0, len(keys)-1)
	cur := wrapOnion(payload, keys)
	for i := 0; i < len(keys)-1; i++ {
		cur = xorBytes(cur, keys[i]) // relay i peels its inbound hop layer
		views = append(views, append([]byte{}, cur...))
	}
	return views
}

// pathID derives a stable identifier for the ordered node chain.
func pathID(nodes []string) string {
	h := sha256.New()
	for i, n := range nodes {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(i))
		h.Write(b[:])
		h.Write([]byte(n))
		h.Write([]byte{0})
	}
	return "path-" + hexShort(h.Sum(nil))
}

func hexShort(b []byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, 12)
	for i := 0; i < 6; i++ {
		out[2*i] = hexd[b[i]>>4]
		out[2*i+1] = hexd[b[i]&0xf]
	}
	return string(out)
}

// transcriptFingerprint binds the key agreement to the public per-link
// round outcomes: both endpoints must observe the same transcript.
func transcriptFingerprint(hops []HopResult) []byte {
	h := sha256.New()
	for _, hop := range hops {
		io.WriteString(h, hop.From)
		io.WriteString(h, "->")
		io.WriteString(h, hop.To)
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], uint64(hop.Round.FinalKeyBits))
		h.Write(b[:])
		binary.LittleEndian.PutUint64(b[:], math.Float64bits(hop.Round.ObservedQBER))
		h.Write(b[:])
	}
	return h.Sum(nil)
}

// ephemeralX25519 deterministically generates an X25519 key pair directly
// from the given derived random source: it reads exactly 32 stream bytes,
// clamps them per RFC 7748 and constructs the private key. We deliberately
// avoid ecdh.GenerateKey because the Go runtime reads extra bytes for an
// internal self-test, whose read-count is not part of the stable contract.
func ephemeralX25519(rng *random.Source) (priv *ecdh.PrivateKey, pubBytes []byte, err error) {
	scalar := make([]byte, 32)
	if _, err := io.ReadFull(rng, scalar); err != nil {
		return nil, nil, err
	}
	scalar[0] &= 248
	scalar[31] &= 127
	scalar[31] |= 64
	priv, err = ecdh.X25519().NewPrivateKey(scalar)
	if err != nil {
		return nil, nil, err
	}
	return priv, priv.PublicKey().Bytes(), nil
}

// ecdhShared computes the X25519 shared secret with the peer's raw public key.
func ecdhShared(priv *ecdh.PrivateKey, peerPub []byte) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(pub)
}

// hkdfSHA256 implements RFC 5869 HKDF-Extract/Expand with the given salt and
// info; returns length bytes (length <= 255*32).
func hkdfSHA256(secret, salt, info []byte, length int) ([]byte, error) {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	prk := hmac.New(sha256.New, salt)
	prk.Write(secret)
	key := prk.Sum(nil)

	out := make([]byte, 0, length)
	var t []byte
	counter := byte(1)
	for len(out) < length {
		mac := hmac.New(sha256.New, key)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		out = append(out, t...)
		counter++
		if counter == 0 {
			return nil, errHKDFTooLong
		}
	}
	return out[:length], nil
}

// deriveE2EKey derives the end-to-end key from the X25519 shared secret,
// binding the QKD path transcript (in the salt) into derivation.
func deriveE2EKey(secret, salt []byte, length int) ([]byte, error) {
	return hkdfSHA256(secret, salt, []byte("qkd-sim/e2e/v1"), length)
}

// confirmTag returns a 16-byte HMAC confirmation tag over salt+transcript.
func confirmTag(key, salt, transcript []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(salt)
	mac.Write(transcript)
	return mac.Sum(nil)[:16]
}
