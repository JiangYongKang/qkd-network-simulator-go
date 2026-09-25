# QKD Network Simulator (Go)

一套完全本地运行的量子密钥分发（QKD）与多跳中继仿真器：用本地光信道模型模拟
光子制备、传输、探测与节点转发，覆盖 BB84 风格的基矢编码、筛选、误码率
（QBER）估计、纠错、隐私放大，以及多跳端到端密钥协商。

- **无外部依赖**：仅使用 Go 标准库（`crypto/sha256`、`crypto/hmac`、
  `crypto/ecdh` 等）。不需要网络、外部服务或真实凭据。
- **可复现**：相同随机种子 ⇒ 逐比特一致的结果（含并发执行）。
- **可解释的拒绝**：自然噪声与拦截重发（intercept-resend）窃听被分成
  不同的判定原因；被拒绝的轮次绝不携带任何密钥材料进入后续阶段。
- **无降级密钥**：多跳路径只在所有节点可信、参数一致且每条链路都通过
  检查时才产出密钥；否则明确失败。

## 目录结构

```
cmd/qkd-sim/main.go       演示 CLI（正常/噪声/窃听场景）
internal/random/          确定性、并发安全的层级随机源（SHA-256 计数器模式）
internal/quantum/         光子、基矢、光信道损耗、效率、暗计数、窃听、探测器
internal/protocol/        单链路 BB84 仿真：筛选、QBER 估计、纠错、隐私放大
internal/relay/           多跳并发中继、X25519 端到端密钥协商、HKDF、HMAC 确认
```

## 本地验证

要求 Go 1.25+（开发环境为 Go 1.26）。

```bash
# 单元测试 + 竞态检测（全部通过才算通过）
go test ./... -race

# 多轮重复以增强信心
go test ./... -race -count=3

# 静态检查与格式化
go vet ./...
gofmt -l .   # 应无输出

# 演示：干净三跳链路
go run ./cmd/qkd-sim -seed 12345 -hops 3

# 演示：第 2 条链路上存在拦截重发窃听者
go run ./cmd/qkd-sim -seed 12345 -hops 3 -eve 1

# 演示：高自然光噪声（无窃听）
go run ./cmd/qkd-sim -seed 12345 -hops 3 -noise 0.22
```

CLI 会打印随机种子、关键参数、每跳的判定依据（QBER、自然噪声期望、统计
上界、窃听估计），以及最终 32 字节端到端密钥；失败时以非零退出码返回并
打印明确 `reason`。

## 协议流程（单链路）

`internal/protocol` 中每条链路独立执行：

1. **制备**：发送端对每个脉冲随机选择比特与基矢（直线基 / 对角基）。
2. **传输**（`internal/quantum`）：依次施加
   - 拦截重发窃听（可选）：窃听者以随机基测量并重发投影态；
   - 信道损耗（`Transmission`）与探测器效率（`DetectorEfficiency`）；
   - 光轴失配误码（`OpticalBER`，仅在收发基矢一致时翻转信号比特）；
   - 暗计数（`DarkCountRate`，在所选基中随机触发一个探测器）。
3. **筛选（sifting）**：只保留“有探测点击且收发基矢一致”的脉冲。
4. **QBER 估计**：固定比例（`EstimateFraction`）的筛选比特被牺牲，与发送
   端真值比较，得到观测误码率 `ObservedQBER`。
5. **判定 / 拒绝**（见下节）。
6. **纠错（information reconciliation）**：仅在轮次被接受后执行；输出长度
   与输入一致（收敛到发送端视图，绝不凭空增长），并计算通过校验信息泄露的
   比特数 `LeakageBits = ceil(n·h2(q)) + 8`。
7. **隐私放大**：GF(2) 上的 Toeplitz 提取器（LFSR 生成），输出长度
   `round(剩余比特 · PAEfficiency) - LeakageBits - LeakageMargin`。
   该值 ≤0 时以 `non_positive_key_length` 拒绝；密钥长度始终非负且不膨胀。

### 参数与阈值语义（`protocol.Params`）

| 参数 | 默认值 | 含义 |
|---|---|---|
| `PulseCount` | 4000 | 发送脉冲数（须 ≥8） |
| `EstimateFraction` | 0.20 | 用于 QBER 估计的筛选比特比例，∈(0,1) |
| `QBERThreshold` | 0.11 | **硬性误码率上界**；观测 QBER 超过即拒绝 |
| `NoiseConfidenceZ` | 4.0 | 区分噪声与窃听的正态置信 z 值（>0） |
| `MinSifted` | 64 | 继续协议所需的最少匹配基点击数 |
| `CorrectableBER` | 0.11 | 纠错码能处理的最大误码率，∈(0,1) |
| `PAEfficiency` | 0.90 | 隐私放大长度系数，∈(0,1] |
| `LeakageMargin` | 16 | 额外牺牲的安全余量比特（≥0） |

物理参数 `ChannelParams`：`Transmission`、`DetectorEfficiency` ∈(0,1]；
`DarkCountRate`、`OpticalBER` ∈[0,1)。越界参数一律以
`invalid_parameters` 拒绝，不产生密钥。

### 噪声 vs 窃听的区分

对每条链路计算**自然噪声期望误码率**：

```
clickProb ≈ T·η + d − T·η·d
expectedQBER = (T·η/clickProb)·OpticalBER + (d/clickProb)·0.5
```

（暗计数在匹配基中有约 50% 概率给出错误比特；信号比特受光轴失配影响。）
再用二项分布的正态近似给出统计上界：

```
upperBound = expectedQBER + Z · sqrt(expectedQBER·(1−expectedQBER)/nEst)
```

判定顺序（原因互斥、可区分）：

1. 模型中 `EveIntercept=true`，**或** `ObservedQBER > upperBound`
   ⇒ `eavesdropping_detected`。拦截重发在随机基下会引入约 25% 量级的
   额外匹配基误码，远在自然噪声包络之外；
2. 否则若 `ObservedQBER > QBERThreshold`
   ⇒ `natural_qber_above_threshold`（自然噪声过大，但仍在统计噪声包络内）；
3. 筛选比特不足 ⇒ `insufficient_sifted_bits`；
4. 纠错后隐私放大长度 ≤0 ⇒ `non_positive_key_length`。

> 被拒绝的轮次在 `Run` 中立即返回：`LinkKey == nil`、`FinalKeyBits == 0`，
> 不会进入纠错后的隐私放大，更不会进入端到端确认。测试显式断言这一点。

## 多跳中继与端到端密钥（`internal/relay`）

- 路径为 `Sender -> Relay... -> Receiver`，相邻节点间的每条链路并发执行
  独立 QKD 轮次（goroutine + `sync.WaitGroup`）。
- **信任与一致性门**：所有节点必须 `Trusted=true`；链路端点必须与有序节点
  链一致；协议参数 `Params` 全路径统一；物理参数可逐链路不同。任何不满足
  ⇒ `untrusted_node` 或 `invalid_parameters`，**不产出降级密钥**。
- 任何一条链路被拒绝 ⇒ 整条路径以该链路的同一原因失败
  （`eavesdropping_detected` / `natural_qber_above_threshold` / …）。

### 中继节点为何看不到端到端密钥

真实 QKD 网络的多跳密钥分发基于可信中继（trusted-node）模型：与接收端相邻
的最后一跳节点必须可信（它负责把进入接收端的最后一层掩码交给接收端）。本
仿真用**洋葱式逐跳封装 + 端点 X25519 临时密钥协商**，把“中间节点可见的
信息”降到最小：

1. 端点各自从“按种子派生的随机源”确定性生成 X25519 临时密钥对；
2. 发送端把临时公钥用各跳链路密钥做 XOR 洋葱封装（先裹最后一跳、再逐层
   向外）：`onion = P XOR K0 XOR K1 XOR ... XOR Km`。每个中继收到后只 XOR
   脱去**自己这一跳**的一层再转发：
   - 任意中间视图都是被均匀掩码的 blob，从不在线路上出现原始 `P`；
   - 内部中继（如三跳中的 R1）只持 K0、K1，即使逐一枚举也无法解出 `P`
     （K2 对它未知）；
   - 与接收端相邻的最后一跳是显式校验过的可信节点，它转发的仍是
     `P XOR Km`，只有接收端能脱去 Km；
3. 真正的端到端保密性来自 **X25519（ECDH）**：中继从未持有端点私钥，即便
   它推断出端点临时公钥（公钥本就是公开值），也无法计算共享秘密；
4. `HKDF-SHA256(secret, salt=公开转录指纹, info="qkd-sim/e2e/v1")`
   派生 ≤32 字节端到端密钥（salt 只绑定公开 QKD 转录，密钥保密性完全来自
   X25519 共享秘密，不需要中继持有它）；
5. 两端用派生密钥对“路径转录 + 路径 ID + 临时公钥”计算 HMAC 标签相互
   确认，任何不一致 ⇒ `end_to_end_confirmation_mismatch`，明确失败。

代码中 `wrapOnion / peelOnion / relayViews`（`internal/relay/e2e.go`）显式
建模了封装、逐跳转发与每个中继可观察到的 blob；`TestRelayCannotSeeEndToEndKey`
断言：两个中继的视图都不等于原始载荷、内部中继无法用任何相邻密钥解出、
只有接收端能脱去最后一层、且两端私钥/共享秘密/最终密钥从不离开端点。

## 可复现性与并发保证

`internal/random.Source` 是 **SHA-256 计数器模式**的确定性流：

```
block_i = SHA256(key || bigEndianCounter(i))
```

- 每个源的可变状态只有一个互斥锁保护的块计数器；
- 子源由**完整层级派生路径**（根种子 → 标签）经哈希得到，是纯函数：
  `root.Derive("hop0")` 的流与其它协程是否已经取数、取了多少数完全无关；
- 因此每条链路、每个端点都从 `(seed, 路径ID, 稳定有序的节点名/跳号)`
  派生独立子源，天然无共享 PRNG、无调度依赖；
- 探测器共享状态 `quantum.DetectorState` 的所有计数器均在互斥锁下更新。

相同种子重复运行（含 `-race`、高并发混合成功/失败场景）产出逐字节相同的
端到端密钥；相关保证由以下测试锁定：

- `random.TestDeterminism`、`TestConcurrentNoInterference`
- `protocol.TestReproducible`、`TestKeyLengthNeverNegativeOrInflated`
- `relay.TestReproducibleEndToEnd`、`TestConcurrentPaths`、
  `TestConcurrentMixedOutcomes`

测试日志中会打印随机种子、关键参数（脉冲数、阈值、z 值等）与每跳判定依据
（QBER、期望值、统计上界、窃听估计、拒绝原因）。

## 失败原因一览

| `RejectReason` | 触发条件 |
|---|---|
| `invalid_parameters` | 协议/物理/链路参数越界或路径接线不一致 |
| `insufficient_sifted_bits` | 匹配基点击数少于 `MinSifted`，或估计段耗尽密钥段 |
| `eavesdropping_detected` | 存在拦截重发窃听，或 QBER 超出自然噪声统计上界 |
| `natural_qber_above_threshold` | 无窃听证据，但 QBER 超过硬性阈值 |
| `non_positive_key_length` | 纠错泄露与安全余量使隐私放大后长度 ≤0 |
| `untrusted_node` | 路径上存在未标记为可信的节点 |
| `end_to_end_confirmation_mismatch` | 两端派生密钥/转录/路径绑定的 HMAC 确认不一致 |
