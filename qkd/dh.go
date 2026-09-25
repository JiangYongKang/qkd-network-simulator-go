package qkd

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
)

// 本文件实现端点间的模拟 Diffie-Hellman 密钥协商。
// 多跳中继中，中间节点只转发 DH 公开值，无法由公开值推出共享秘密，
// 因此无法获得端到端密钥内容（计算性安全假设）。

// dhPrimeHex 是 RFC 2409 第二组（1024 位 MODP）的素数。
const dhPrimeHex = `
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
29024E088A67CC74020BBEA63B139B22514A08798E3404DD
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381
FFFFFFFFFFFFFFFF`

var dhGroup = struct {
	p, g *big.Int
}{}

func init() {
	p, ok := new(big.Int).SetString(stripSpaces(dhPrimeHex), 16)
	if !ok {
		panic("qkd: 无法解析 DH 群参数")
	}
	dhGroup.p = p
	dhGroup.g = big.NewInt(2)
}

func stripSpaces(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\n' || c == '\t' || c == '\r' {
			continue
		}
		out = append(out, c)
	}
	return string(out)
}

// dhGenerate 生成一对 DH 私钥/公钥，随机性来自给定随机源（可复现）。
func dhGenerate(rng *LockedSource) (priv, pub *big.Int) {
	raw := rng.Bytes(32)
	priv = new(big.Int).SetBytes(raw)
	// 把私钥约束在 [2, p-2]。
	mod := new(big.Int).Sub(dhGroup.p, big.NewInt(3))
	priv.Mod(priv, mod).Add(priv, big.NewInt(2))
	pub = new(big.Int).Exp(dhGroup.g, priv, dhGroup.p)
	return priv, pub
}

// dhShared 由对方公钥与己方私钥计算共享秘密。
// 对方公钥非法（不在 [2, p-2]）时返回 nil。
func dhShared(pub, priv *big.Int) *big.Int {
	if pub == nil || priv == nil {
		return nil
	}
	two := big.NewInt(2)
	upper := new(big.Int).Sub(dhGroup.p, two)
	if pub.Cmp(two) < 0 || pub.Cmp(upper) > 0 {
		return nil
	}
	return new(big.Int).Exp(pub, priv, dhGroup.p)
}

// dhDeriveKey 把共享秘密哈希为定长密钥（SHA-256 计数器模式）。
func dhDeriveKey(shared *big.Int, label string, outBytes int) []byte {
	if shared == nil || outBytes <= 0 {
		return nil
	}
	secret := shared.Bytes()
	out := make([]byte, 0, outBytes)
	var ctr [4]byte
	for len(out) < outBytes {
		h := sha256.New()
		h.Write([]byte("qkd-dh:"))
		h.Write([]byte(label))
		h.Write(secret)
		binary.BigEndian.PutUint32(ctr[:], uint32(len(out)/sha256.Size))
		h.Write(ctr[:])
		out = h.Sum(out)
	}
	return out[:outBytes]
}
