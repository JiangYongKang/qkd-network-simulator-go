package qkd

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"math"
)

// 本文件实现经典后处理：二元熵、Cascade 式纠错、隐私放大与密钥确认。
// 所有函数均为确定性实现，相同输入必得相同输出。

// h2 计算二元熵（比特）。p 超出 (0,1) 时返回边界值 0。
func h2(p float64) float64 {
	if p <= 0 || p >= 1 {
		return 0
	}
	return -p*math.Log2(p) - (1-p)*math.Log2(1-p)
}

// cascadeBlockSizes 由首轮块长 k1 与比特数 n 给出各轮块大小：
// 先倍增四轮（标准 CASCADE），再补充两轮小块，拆分始终同块的错误对。
func cascadeBlockSizes(k1, n int) []int {
	sizes := []int{k1, 2 * k1, 4 * k1, 8 * k1, k1 / 2, k1 / 4}
	for i, s := range sizes {
		if s < 4 {
			s = 4
		}
		if s > n {
			s = n
		}
		sizes[i] = s
	}
	return sizes
}

// cascadeCorrect 执行 CASCADE 式纠错：每轮把比特按确定性随机置换分块，
// 比较每块奇偶性，不一致的块内二分定位并翻转一个错误比特；
// 每次翻转后回溯检查此前各轮包含该位置的块（奇偶性可能因此改变），
// 递归修复，从而清除同块偶数错误。纠错只修改 b（接收方），a 保持不变；
// leaked 统计公开的奇偶比特数。输出长度与输入相同，密钥不会凭空增长。
func cascadeCorrect(a, b []int, qber float64, rng *LockedSource) (corrA, corrB []int, leaked int) {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	corrA = append([]int(nil), a[:n]...)
	corrB = append([]int(nil), b[:n]...)
	if n == 0 {
		return corrA, corrB, 0
	}

	// 首轮块长按 0.73/qber 估计；qber 过小（含 0）时用 1/n 作下限，
	// 避免块长退化为极小值导致奇偶泄露过大。
	qeff := qber
	if floor := 1.0 / float64(n); qeff < floor {
		qeff = floor
	}
	k1 := int(0.73 / qeff)
	if k1 < 4 {
		k1 = 4
	}
	if k1 > n {
		k1 = n
	}

	var knownBlocks [][]int
	var fixBlock func(idx []int)
	fixBlock = func(idx []int) {
		leaked++ // 块整体奇偶比较
		if parityOf(corrA, idx) == parityOf(corrB, idx) {
			return
		}
		lo, hi := 0, len(idx)
		for hi-lo > 1 {
			mid := (lo + hi) / 2
			leaked++ // 二分过程的奇偶比较
			if parityOf(corrA, idx[lo:mid]) != parityOf(corrB, idx[lo:mid]) {
				hi = mid
			} else {
				lo = mid
			}
		}
		pos := idx[lo]
		corrB[pos] ^= 1
		// 回溯：此前块若包含被翻转的位置，奇偶性可能已改变。
		for _, bl := range knownBlocks {
			if containsInt(bl, pos) {
				fixBlock(bl)
			}
		}
	}

	for _, blockSize := range cascadeBlockSizes(k1, n) {
		perm := permute(n, rng)
		passStart := len(knownBlocks)
		for start := 0; start < n; start += blockSize {
			end := start + blockSize
			if end > n {
				end = n
			}
			knownBlocks = append(knownBlocks, perm[start:end])
		}
		for _, bl := range knownBlocks[passStart:] {
			fixBlock(bl)
		}
	}
	return corrA, corrB, leaked
}

// containsInt 报告切片是否包含指定值。
func containsInt(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// permute 生成 [0,n) 的确定性随机置换（Fisher-Yates）。
func permute(n int, rng *LockedSource) []int {
	perm := make([]int, n)
	for i := range perm {
		perm[i] = i
	}
	for i := n - 1; i > 0; i-- {
		j := rng.Intn(i + 1)
		perm[i], perm[j] = perm[j], perm[i]
	}
	return perm
}

// parityOf 计算 bits 在 idx 指定位置上的奇偶性。
func parityOf(bits []int, idx []int) int {
	p := 0
	for _, i := range idx {
		p ^= bits[i] & 1
	}
	return p
}

// privacyAmplify 使用基于 SHA-256 计数器模式的通用哈希，
// 把输入比特压缩为 outBits 比特密钥。outBits <= 0 时返回 nil。
func privacyAmplify(key []int, outBits int, label string) []byte {
	if outBits <= 0 || len(key) == 0 {
		return nil
	}
	outBytes := (outBits + 7) / 8
	raw := bitsToBytes(key)
	out := make([]byte, 0, outBytes)
	var ctr [4]byte
	for len(out) < outBytes {
		h := sha256.New()
		h.Write([]byte("qkd-pa:"))
		h.Write([]byte(label))
		h.Write(raw)
		binary.BigEndian.PutUint32(ctr[:], uint32(len(out)/sha256.Size))
		h.Write(ctr[:])
		out = h.Sum(out)
	}
	out = out[:outBytes]
	// 屏蔽最后一个字节中多余的比特，保证长度语义精确。
	if rem := outBits % 8; rem != 0 {
		out[outBytes-1] &= 0xFF << (8 - rem)
	}
	return out
}

// confirmationTag 计算密钥确认标签（HMAC-SHA256 截断 16 字节）。
func confirmationTag(key []byte, label string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("qkd-confirm:"))
	m.Write([]byte(label))
	return m.Sum(nil)[:16]
}

// bitsToBytes 将比特切片打包为字节（高位在前）。
func bitsToBytes(bits []int) []byte {
	if len(bits) == 0 {
		return nil
	}
	out := make([]byte, (len(bits)+7)/8)
	for i, b := range bits {
		if b&1 == 1 {
			out[i/8] |= 1 << (7 - uint(i%8))
		}
	}
	return out
}
