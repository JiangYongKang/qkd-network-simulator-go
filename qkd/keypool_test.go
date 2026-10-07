package qkd

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
)

// TestKeyPoolCapacityAndNoReissue 覆盖容量上限与“不重复发放”：
// 池满后 OverflowReject 策略拒绝登记；消费即移除，取空后无密钥可发。
func TestKeyPoolCapacityAndNoReissue(t *testing.T) {
	pool, err := NewKeyPool(3, OverflowReject)
	if err != nil {
		t.Fatalf("创建密钥池失败: %v", err)
	}
	t.Logf("[pool-cap] capacity=%d policy=%s", pool.Capacity(), OverflowReject)
	for i := 0; i < 5; i++ {
		ok := pool.Deposit(i, []byte{byte(i), 0xAA})
		t.Logf("[pool-cap] deposit round=%d ok=%v available=%d", i, ok, pool.Available())
		if i < 3 && !ok {
			t.Fatalf("第 %d 轮应入池成功", i)
		}
		if i >= 3 && ok {
			t.Fatalf("池满后第 %d 轮应被拒绝", i)
		}
	}
	st := pool.Stats()
	t.Logf("[pool-cap] stats=%+v", st)
	if st.Deposited != 3 || st.Dropped != 2 {
		t.Fatalf("统计不符: %+v", st)
	}
	seen := make(map[byte]bool)
	for pool.Available() > 0 {
		e, ok := pool.Consume()
		if !ok {
			t.Fatalf("available=%d 时应能消费", pool.Available())
		}
		t.Logf("[pool-cap] consume round=%d key=%x remaining=%d", e.Round, e.Key, pool.Available())
		if seen[e.Key[0]] {
			t.Fatalf("密钥被重复发放: round=%d", e.Round)
		}
		seen[e.Key[0]] = true
	}
	if _, ok := pool.Consume(); ok {
		t.Fatalf("池空后不得再发放密钥")
	}
	if got := pool.Stats().Consumed; got != 3 {
		t.Fatalf("消费统计应为 3，得到 %d", got)
	}
}

// TestKeyPoolDropOldest 覆盖 drop-oldest 策略：池满时最旧密钥被顶替。
func TestKeyPoolDropOldest(t *testing.T) {
	pool, err := NewKeyPool(2, OverflowDropOldest)
	if err != nil {
		t.Fatalf("创建密钥池失败: %v", err)
	}
	for i := 0; i < 4; i++ {
		pool.Deposit(i, []byte{byte(i)})
	}
	t.Logf("[pool-drop] stats=%+v available=%d", pool.Stats(), pool.Available())
	if pool.Stats().Dropped != 2 {
		t.Fatalf("应有 2 条最旧密钥被顶替，得到 %d", pool.Stats().Dropped)
	}
	e1, _ := pool.Consume()
	e2, _ := pool.Consume()
	t.Logf("[pool-drop] consumed rounds: %d, %d", e1.Round, e2.Round)
	if e1.Round != 2 || e2.Round != 3 {
		t.Fatalf("池中应只剩第 2、3 轮密钥，得到 %d、%d", e1.Round, e2.Round)
	}
}

// TestSessionReproducible 同一种子下整个多轮序列（产出+消费记录与
// 实际发放的密钥）完全可复现。
func TestSessionReproducible(t *testing.T) {
	cfg := SessionConfig{
		Rounds:       6,
		Nodes:        trustedPath(3, DefaultRoundConfig().Channel),
		Relay:        DefaultRoundConfig(),
		ConsumeEvery: 2,
	}
	const seed = 777
	run := func() SessionResult {
		pool, _ := NewKeyPool(8, OverflowReject)
		return RunSession(cfg, pool, seed)
	}
	r1 := run()
	r2 := run()
	for i := range r1.Records {
		a, b := r1.Records[i], r2.Records[i]
		t.Logf("[session-repro] seed=%d round=%d accepted=%v deposited=%v consumed=%v",
			seed, a.Round, a.Accepted, a.Deposited, a.Consumed)
		if a != b {
			t.Fatalf("第 %d 轮记录不一致: %+v vs %+v", i, a, b)
		}
	}
	if r1.Stats != r2.Stats || r1.FinalAvailable != r2.FinalAvailable {
		t.Fatalf("统计不一致: %+v/%d vs %+v/%d", r1.Stats, r1.FinalAvailable, r2.Stats, r2.FinalAvailable)
	}
	t.Logf("[session-repro] stats=%+v finalAvailable=%d", r1.Stats, r1.FinalAvailable)
	// 直接核对两轮密钥内容可复现：用相同种子重放单轮中继。
	for i := 0; i < cfg.Rounds; i++ {
		roundSeed := deriveSeed(seed, fmt.Sprintf("session-round-%d", i))
		k1 := RunRelay(cfg.Nodes, cfg.Relay, roundSeed)
		k2 := RunRelay(cfg.Nodes, cfg.Relay, roundSeed)
		if k1.Accepted != k2.Accepted || !bytes.Equal(k1.Key, k2.Key) {
			t.Fatalf("第 %d 轮密钥在同种子下不一致", i)
		}
	}
}

// TestSessionPoolFull 池容量有限且不消费时，装满后的轮次按规则被拒绝，
// 且拒绝情况在记录中可见。
func TestSessionPoolFull(t *testing.T) {
	cfg := SessionConfig{
		Rounds: 5,
		Nodes:  trustedPath(2, DefaultRoundConfig().Channel),
		Relay:  DefaultRoundConfig(),
	}
	const seed = 31
	pool, _ := NewKeyPool(2, OverflowReject)
	res := RunSession(cfg, pool, seed)
	deposited, refused := 0, 0
	for _, rec := range res.Records {
		t.Logf("[session-full] seed=%d capacity=2 round=%d accepted=%v deposited=%v",
			seed, rec.Round, rec.Accepted, rec.Deposited)
		if !rec.Accepted {
			t.Fatalf("默认参数下第 %d 轮应成功，reason=%s", rec.Round, rec.Reason)
		}
		if rec.Deposited {
			deposited++
		} else {
			refused++
		}
	}
	t.Logf("[session-full] deposited=%d refused=%d stats=%+v", deposited, refused, res.Stats)
	if deposited != 2 || refused != 3 {
		t.Fatalf("容量 2 的池应收 2 拒 3，得到收 %d 拒 %d", deposited, refused)
	}
	if res.FinalAvailable != 2 {
		t.Fatalf("最终可用应为 2，得到 %d", res.FinalAvailable)
	}
}

// TestKeyPoolConcurrent 并发登记与消费在竞态检测下无数据竞争，
// 且总量守恒：已消费 + 可用 + 丢弃 == 登记尝试总数。
func TestKeyPoolConcurrent(t *testing.T) {
	pool, _ := NewKeyPool(4, OverflowDropOldest)
	const workers = 8
	const perWorker = 50
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(2)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				pool.Deposit(w*perWorker+i, []byte{byte(w), byte(i)})
			}
		}(w)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				pool.Consume()
			}
		}()
	}
	wg.Wait()
	st := pool.Stats()
	t.Logf("[pool-concurrent] stats=%+v available=%d", st, pool.Available())
	// drop-oldest 策略下：每次登记尝试都计入 Deposited，
	// 被顶替的条目计入 Dropped，故 已消费 + 可用 + 丢弃 == 已登记。
	if st.Consumed+pool.Available()+st.Dropped != st.Deposited {
		t.Fatalf("守恒关系破坏: consumed=%d available=%d dropped=%d deposited=%d",
			st.Consumed, pool.Available(), st.Dropped, st.Deposited)
	}
	if st.Deposited != workers*perWorker {
		t.Fatalf("登记尝试总数不符: deposited=%d total=%d", st.Deposited, workers*perWorker)
	}
}
