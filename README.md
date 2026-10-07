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
- **多轮密钥池**：连续多轮成功产出的端到端密钥按轮次登记进容量受限的
  密钥池；消费按 FIFO 发放且每条密钥只发放一次；池满时按明确策略
  （拒绝新密钥或排队）处理；同一种子的整个多轮序列（产出与消费记录）
  完全可复现。
- **逐跳一致性核验**：对中继结果逐跳核对协商参数、轮次结果与握手凭据
  （HMAC 复算）；任一跳对不上，整条端到端流程判定失败，失败轮次
  没有任何密钥材料流向后续环节。
- **链路切换与重试**：同一会话内对多条候选路径按序尝试、每条路径可重试；
  链路时好时坏或某跳短时不可用时自动切换/重试；只要还有可信路径就正常
  产出密钥，全部不可用时明确失败，绝不产出降级密钥。
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
  `ReasonInvalidParams`、`ReasonUntrustedNode`、`ReasonParamMismatch`、
  `ReasonHopVerifyFailed`（逐跳核验未通过）、`ReasonLinkUnavailable`
  （切换/重试场景下链路当前不可用）、`ReasonNoUsablePath`
  （所有候选路径均不可信或不可用）。
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

## 多轮密钥池语义

`KeyPool`（`NewKeyPool(capacity, policy)`）是多轮会话的统一密钥池，
并发安全，规则如下：

- **登记**：`RunSession(nodes, cfg, seed, rounds, pool)` 连续执行多轮
  中继（每轮种子按 `session-round-i` 标签派生），成功轮次的端到端密钥
  按轮次号登记进池；失败轮次不登记、不携带密钥材料。
- **容量上限**：池中未发放密钥数任何时候都不超过 `capacity`。
- **池满策略**（二选一，构造时确定）：
  - `PoolRejectNew`：新密钥直接被拒并计入 `Rejected()`，该轮密钥丢弃；
  - `PoolQueue`：新密钥进入等待队列，`Consume` 释放空间后按 FIFO 补入。
- **消费**：`Consume()` 按 FIFO 发放，已发放的密钥从池中移除，
  **不会再次发放**；`Available()` 随时返回当前可发放数量。
- **可复现**：同一种子 + 同一参数的 `RunSession` 产出完全相同的轮次
  序列、登记/拒绝计数与消费序列。

## 逐跳一致性核验语义

`VerifyRelayHops(nodes, cfg, relayResult)` 对每一跳依次核对：

1. 两个端点节点可信，且其 `ExpectedChannel` 与会话参数一致；
2. 链路端点标识与路径一致、该跳 BB84 轮次被接受、链路密钥非空；
3. 正/反方向的握手凭据（转发时用链路密钥计算的 HMAC）能用该跳
   链路密钥对握手消息复算一致。

任一跳任一项对不上，该跳 `HopCheck.OK=false` 并给出中文判定依据。
`RunRelayVerified(nodes, cfg, seed)` 在中继成功后自动执行逐跳核验：
存在失败跳时整体以 `ReasonHopVerifyFailed` 失败、`Key` 置空，
**密钥材料不进入后续环节**；不存在"参数不一致却照样出密钥"的路径。

## 链路切换与重试语义

`RunRelayWithFailover(paths, cfg, seed, maxRetries, healthy)`：

- 按顺序尝试候选路径，每条路径最多 `maxRetries` 次（含首次）；
- `healthy(path, attempt)` 是调用方提供的健康探针，模拟链路时好时坏
  或短时不可用；不可用或中继/核验失败都记录为一次 `PathAttempt`
  （含路径、尝试序号、拒绝原因与细节），然后重试或切换下一条路径；
- 任一尝试成功即产出端到端密钥并返回 `PathUsed`；
- 所有路径的所有尝试都失败时以 `ReasonNoUsablePath` 明确失败，
  `Key` 为空，**绝不把降级结果当作成功密钥**；
- 每次尝试的种子按 `failover-p<路径>-a<尝试>` 派生，同一种子下整个
  尝试序列与产出完全可复现。

## 兼容范围

- 仅依赖 Go 标准库，要求 Go 1.25+；不涉及任何外部服务、真实凭据或
  真实量子硬件，全部在本地仿真。
- 新增 API（`KeyPool`/`RunSession`/`VerifyRelayHops`/`RunRelayVerified`/
  `RunRelayWithFailover`）为纯增量；`RunRelay`、`RunBB84Round` 等原有
  入口的签名与判定语义不变。`RelayResult`/`LinkResult` 新增了握手凭据
  字段（`HandshakeFwd/Bwd`、`FwdTag/BwdTag`），仅追加不修改既有字段。
- 注意：因中继现在记录握手凭据，同一种子的 `RelayResult` 会多出凭据
  字段，但密钥、轮次统计与判定结论与之前完全一致。

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
go test -v -run 'TestKeyPool|TestSession' ./qkd/   # 密钥池场景与种子
go test -v -run 'TestHopVerify' ./qkd/             # 逐跳核验判定依据
go test -v -run 'TestFailover' ./qkd/              # 切换/重试尝试序列
```

测试覆盖：可复现性（同种子同密钥、同种子多轮会话序列、同种子切换/
重试序列）、窃听与噪声的区分（含部分拦截、高噪声不误判为窃听）、
密钥池（容量上限、拒绝/排队策略、不重复发放、并发守恒）、逐跳核验
（篡改链路密钥/握手消息/参数不一致/链路被拒均判失败且无密钥流出）、
链路切换与重试（时好时坏重试成功、切换备用路径、全部不可用明确失败、
不可信路径不降级）、并发执行（共享随机源、多路径并行、并发切换会话、
并发登记消费）、参数边界（非法参数、高损耗、损耗-密钥率单调性）与
失败原因可区分性。所有用例在 `go test -race` 下通过。
