package qkd

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
)

// TestKeyPoolCapacityAndNoReissue 覆盖：容量上限、PoolRejectNew 拒绝规则、
// 已发放密钥不重复发放、可用数量随时可查。
func TestKeyPoolCapacityAndNoReissue(t *testing.T) {
	const capacity = 3
	pool := NewKeyPool(capacity, PoolRejectNew)
	t.Logf("[keypool] 场景=容量与拒绝 策略=%s 容量=%d", PoolRejectNew, capacity)

	keys := [][]byte{[]byte("k0"), []byte("k1"), []byte("k2"), []byte("k3"), []byte("k4")}
	for i, k := range keys {
		ok := pool.Register(i, k)
		t.Logf("[keypool] 登记 round=%d -> %v", i, ok)
		if i < capacity && !ok {
			t.Fatalf("容量内登记应成功：round=%d", i)
		}
		if i >= capacity && ok {
			t.Fatalf("池满后 PoolRejectNew 应拒绝：round=%d", i)
		}
	}
	if pool.Available() != capacity {
		t.Fatalf("可用数应为 %d，得到 %d", capacity, pool.Available())
	}
	if pool.Rejected() != len(keys)-capacity {
		t.Fatalf("拒绝数应为 %d，得到 %d", len(keys)-capacity, pool.Rejected())
	}

	// 逐条消费：每条密钥只发放一次，且互不相同。
	seen := map[string]int{}
	for i := 0; i < capacity; i++ {
		rec, ok := pool.Consume()
		if !ok {
			t.Fatalf("第 %d 次消费应成功", i)
		}
		if !rec.Consumed {
			t.Fatalf("发放的记录应标记为已消费")
		}
		seen[string(rec.Key)]++
		t.Logf("[keypool] 消费 round=%d 剩余可用=%d", rec.Round, pool.Available())
	}
	if len(seen) != capacity {
		t.Fatalf("发放的密钥不得重复：%d 条中去重后 %d 条", capacity, len(seen))
	}
	if _, ok := pool.Consume(); ok {
		t.Fatalf("池空后不得再发放密钥")
	}
	if pool.Available() != 0 {
		t.Fatalf("池空后可用数应为 0，得到 %d", pool.Available())
	}
}

// TestKeyPoolQueuePolicy 覆盖：PoolQueue 策略下溢出密钥排队，
// 消费释放空间后按 FIFO 补入。
func TestKeyPoolQueuePolicy(t *testing.T) {
	const capacity = 2
	pool := NewKeyPool(capacity, PoolQueue)
	t.Logf("[keypool] 场景=排队策略 策略=%s 容量=%d", PoolQueue, capacity)

	for i := 0; i < 4; i++ {
		if !pool.Register(i, []byte(fmt.Sprintf("q%d", i))) {
			t.Fatalf("PoolQueue 策略下登记不应被拒绝：round=%d", i)
		}
	}
	if pool.Available() != capacity || pool.Pending() != 2 {
		t.Fatalf("应有 %d 可用、2 排队，得到 可用=%d 排队=%d",
			capacity, pool.Available(), pool.Pending())
	}
	// 消费两条后，排队的两条应按 FIFO 补入。
	var order []int
	for i := 0; i < 4; i++ {
		rec, ok := pool.Consume()
		if !ok {
			t.Fatalf("第 %d 次消费应成功（排队补入）", i)
		}
		order = append(order, rec.Round)
		t.Logf("[keypool] 消费 round=%d 可用=%d 排队=%d", rec.Round, pool.Available(), pool.Pending())
	}
	for i, r := range order {
		if r != i {
			t.Fatalf("发放顺序应为 FIFO 0,1,2,3，得到 %v", order)
		}
	}
	if pool.Rejected() != 0 {
		t.Fatalf("PoolQueue 策略下不应有拒绝记录，得到 %d", pool.Rejected())
	}
}

// TestKeyPoolInvalid 覆盖非法构造与非法登记。
func TestKeyPoolInvalid(t *testing.T) {
	if NewKeyPool(0, PoolRejectNew) != nil {
		t.Fatalf("容量非正应返回 nil")
	}
	pool := NewKeyPool(1, PoolRejectNew)
	if pool.Register(0, nil) {
		t.Fatalf("空密钥不得登记")
	}
	if pool.Available() != 0 {
		t.Fatalf("空密钥登记后可用数应为 0")
	}
}

// TestSessionKeyPoolReproducible 覆盖：多轮会话把成功轮次密钥登记进池，
// 同一种子的整个多轮序列（产出与消费记录）完全可复现。
func TestSessionKeyPoolReproducible(t *testing.T) {
	cfg := DefaultRoundConfig()
	nodes := trustedPath(3, cfg.Channel)
	const seed = 777
	const rounds = 6
	const capacity = 4
	t.Logf("[session] 场景=多轮密钥池可复现 seed=%d 轮次=%d 容量=%d 策略=%s",
		seed, rounds, capacity, PoolRejectNew)

	run := func() (SessionResult, []KeyRecord) {
		pool := NewKeyPool(capacity, PoolRejectNew)
		sr := RunSession(nodes, cfg, seed, rounds, pool)
		var consumed []KeyRecord
		for {
			rec, ok := pool.Consume()
			if !ok {
				break
			}
			consumed = append(consumed, rec)
		}
		return sr, consumed
	}
	sr1, consumed1 := run()
	sr2, consumed2 := run()

	t.Logf("[session] 第一次：登记=%d 拒绝=%d 消费=%d", sr1.Registered, sr1.RejectedByPool, len(consumed1))
	t.Logf("[session] 第二次：登记=%d 拒绝=%d 消费=%d", sr2.Registered, sr2.RejectedByPool, len(consumed2))

	if sr1.Registered != sr2.Registered || sr1.RejectedByPool != sr2.RejectedByPool {
		t.Fatalf("同种子两次会话的登记/拒绝记录应一致")
	}
	if len(consumed1) != len(consumed2) {
		t.Fatalf("同种子两次会话的消费序列长度应一致")
	}
	for i := range consumed1 {
		if consumed1[i].Round != consumed2[i].Round || !bytes.Equal(consumed1[i].Key, consumed2[i].Key) {
			t.Fatalf("第 %d 条消费记录在同种子下应完全一致", i)
		}
	}
	// 容量规则：登记数 = min(成功轮次, 容量)，其余成功轮次被池拒绝。
	accepted := 0
	for i, rr := range sr1.Rounds {
		if rr.Accepted {
			accepted++
		}
		t.Logf("[session] 轮次=%d accepted=%v reason=%s", i, rr.Accepted, rr.Reason)
	}
	wantRegistered := accepted
	if wantRegistered > capacity {
		wantRegistered = capacity
	}
	if sr1.Registered != wantRegistered || sr1.RejectedByPool != accepted-wantRegistered {
		t.Fatalf("容量规则不符：登记=%d 拒绝=%d（成功轮次=%d 容量=%d）",
			sr1.Registered, sr1.RejectedByPool, accepted, capacity)
	}
	// 消费序列中的密钥互不相同（不重复发放）。
	seen := map[string]bool{}
	for _, rec := range consumed1 {
		if seen[string(rec.Key)] {
			t.Fatalf("消费序列中出现重复密钥（round=%d）", rec.Round)
		}
		seen[string(rec.Key)] = true
	}
	// 失败轮次不得有密钥材料。
	for i, rr := range sr1.Rounds {
		if !rr.Accepted && rr.Key != nil {
			t.Fatalf("第 %d 轮失败却携带密钥材料", i)
		}
	}
}

// TestKeyPoolConcurrent 并发登记/消费在竞态检测下无数据竞争，
// 且发放守恒：每条密钥最多发放一次、发放的都是登记过的密钥。
func TestKeyPoolConcurrent(t *testing.T) {
	const capacity = 16
	const producers = 8
	const perProducer = 8
	pool := NewKeyPool(capacity, PoolRejectNew)
	t.Logf("[keypool] 场景=并发登记消费 容量=%d 生产者=%d 每者=%d 策略=%s",
		capacity, producers, perProducer, PoolRejectNew)

	var wg sync.WaitGroup
	for w := 0; w < producers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perProducer; i++ {
				pool.Register(w*perProducer+i, []byte(fmt.Sprintf("w%d-k%d", w, i)))
			}
		}(w)
	}
	consumed := make(chan KeyRecord, producers*perProducer)
	for c := 0; c < 4; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				rec, ok := pool.Consume()
				if !ok {
					return
				}
				consumed <- rec
			}
		}()
	}
	wg.Wait()
	close(consumed)
	seen := map[string]bool{}
	n := 0
	for rec := range consumed {
		if seen[string(rec.Key)] {
			t.Fatalf("并发消费出现重复发放：round=%d", rec.Round)
		}
		seen[string(rec.Key)] = true
		n++
	}
	t.Logf("[keypool] 并发消费总数=%d（登记上限 %d）", n, producers*perProducer)
	if n > producers*perProducer {
		t.Fatalf("消费总数不应超过登记总数 %d，得到 %d", producers*perProducer, n)
	}
	if pool.Available() > capacity {
		t.Fatalf("可用数不应超过容量 %d，得到 %d", capacity, pool.Available())
	}
}
