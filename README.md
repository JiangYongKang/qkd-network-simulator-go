# QKD Network Simulator (Go)

本地量子密钥分发（BB84）与多跳中继仿真。使用本地光信道模型模拟光子传输、
探测与节点转发，不依赖任何外部服务或真实凭据，仅使用 Go 标准库。

## 功能概览

- **单链路 BB84**：基矢编码、筛选、误码率（QBER）估计、Cascade 式纠错、
  隐私放大与密钥确认。信道损耗、探测器效率、暗计数与去极化噪声都会影响
  最终密钥长度。
- **噪声与窃听区分**：支持拦截-重发式窃听（Eve）模型；协议依据抽样误码率
  与自然噪声基线的偏离程度给出误码归因（自然噪声 / 窃听），超阈值轮次
  一律拒绝且不携带任何密钥材料进入后处理。
- **多跳中继**：相邻节点并行执行 BB84 得到链路密钥；端点通过逐跳转发
  （链路密钥 HMAC 认证）的 Diffie-Hellman 协商得到端到端密钥，中间节点
  只见到链路密钥与 DH 公开值，无法获得端到端密钥内容。
- **并发与可复现**：所有随机性来自确定性 `LockedSource`；子流按标签派生，
  与并发调度顺序无关，相同种子结果完全一致；`go test -race` 无数据竞争。

## 协议参数与阈值语义

### ChannelParams（信道物理参数）

| 参数 | 含义 | 合法范围 |
|---|---|---|
| `LossDB` | 信道损耗（分贝） | `>= 0` |
| `DetectorEfficiency` | 单光子探测器效率 | `(0,1]` |
| `DarkCountProb` | 每脉冲时隙暗计数概率 | `[0,1)` |
| `DepolarizationProb` | 自然去极化噪声概率 | `[0,1)` |

单脉冲探测率 ≈ `10^(-LossDB/10) * DetectorEfficiency + DarkCountProb`。
自然噪声基线 QBER ≈ `(η·depol/2 + dark/2) / (η + dark)`，
其中信号误码来自去极化（贡献 `depol/2`），暗计数贡献随机比特（`1/2`）。

### RoundConfig（协议参数）

| 参数 | 含义 | 合法范围 |
|---|---|---|
| `NumPulses` | 一轮发送的脉冲数 | `> 0` |
| `Eve.InterceptProb` | 每个脉冲被拦截-重发的概率 | `[0,1]` |
| `SampleFraction` | 用于 QBER 估计的筛选比特抽样比例（抽样比特被公开销毁） | `(0,1)` |
| `QBERThreshold` | 可接受的最大抽样误码率，超过即拒绝该轮 | `(0,1)` |
| `MinSiftedBits` | 进入后处理所需的最少筛选比特数 | `> 0` |
| `SecurityBits` | 隐私放大安全余量（比特） | `>= 0` |

### 误码归因与拒绝原因

- 抽样 QBER 超过 `NaturalBaseline + 5σ`（σ 为抽样统计涨落，基线不低于
  `1/样本数`）时归因为 **窃听**（`AttributionEavesdrop`），拒绝原因为
  `ReasonEavesdropSuspected`；
- QBER 超过 `QBERThreshold` 但未显著偏离自然基线时归因为 **自然噪声**
  （`AttributionNaturalNoise`），拒绝原因为 `ReasonQBERTooHigh`；
- 其余拒绝原因：`ReasonInsufficientKey`（筛选比特不足或隐私放大后长度
  非正）、`ReasonConfirmationFailed`（纠错后双方密钥确认不一致）、
  `ReasonInvalidParams`、`ReasonUntrustedNode`、`ReasonParamMismatch`。
- **任何被拒轮次 `Key` 恒为 `nil`**，不携带密钥材料进入后续阶段。
- `RoundResult.TrueNoiseErrors / TrueEveErrors` 是仿真“事实”计数，
  用于测试核对判定结论与真实误码来源一致。

### 密钥长度语义

- 筛选只丢弃比特，纠错（CASCADE）只翻转比特不增加比特；
- 最终密钥长度 `= floor(纠错后长度 × (1 - h2(QBER))) - 泄露奇偶比特 - SecurityBits`，
  结果不为正时该轮以 `ReasonInsufficientKey` 失败，**密钥长度不会为负、
  不会凭空增长**。

## 多跳中继语义

`RunRelay(nodes, cfg, seed)`：

1. 所有节点必须 `Trusted=true`，且每个节点的 `ExpectedChannel` 与
   `cfg.Channel` 完全一致，否则分别以 `ReasonUntrustedNode` /
   `ReasonParamMismatch` 明确失败；
2. 各相邻链路**并行**执行 BB84（每条链路使用按 `link-i` 标签派生的
   独立随机流）；任一链路被拒，整体以该链路的拒绝原因失败；
3. 端点 DH 公开值沿路径逐跳转发，每跳用链路密钥做 HMAC 认证；
   端点各自由 DH 共享秘密导出 32 字节端到端密钥；
4. 中间节点只持有相邻链路密钥与 DH 公开值，**无法推出端到端密钥**
   （计算性安全假设）；整体失败时 `Key` 为空，绝不产出降级密钥。

## 可复现性与并发保证

- 全部随机性来自 `NewLockedSource(seed)`；相同种子 + 相同参数 ⇒
  完全相同的密钥与全部中间统计量。
- 子随机流通过 `Derive(label)` 以 FNV-1a 混合派生，**不消耗父流**，
  因此派生与调用顺序、goroutine 调度无关，并发执行结果与串行一致。
- `LockedSource` 内部以互斥锁保护，多 goroutine 共享同一随机源在
  `go test -race` 下无数据竞争。
- 中继的各链路结果写入各自的下标，无共享可变状态。

## 本地验证

```bash
go build ./...          # 编译
go vet ./...            # 静态检查
go test ./...           # 单元测试（日志含随机种子、关键参数与判定依据）
go test -race ./...     # 竞态检测
go test -v -run TestEavesdropDetected ./qkd/   # 查看单次判定依据
```

测试覆盖：可复现性（同种子同密钥）、窃听与噪声的区分（含部分拦截、
高噪声不误判为窃听）、并发执行（共享随机源、多路径并行）、参数边界
（非法参数、高损耗、损耗-密钥率单调性）与失败原因可区分性。
