# 离线安全复核器 12731（Go / Windows / 仅标准库）

日志机房送来三份**合成的、已封存的副本**：有的缺整段、有的在同一序号给出不同的
前序摘要、分区交接记录还可能被后来的有效撤销作废。本仓库用 Go 实现了一个完全离线的
复核器，把三件事严格分开：

1. 从**受信起点**能够唯一接出的**最长前缀**；
2. **最早已证冲突**（同一 `(分区,序号)` 出现两个不同前序摘要，且二者当前都有效）；
3. 接不上、但也**不能证明矛盾**的**未证区间**（缺段 / 孤证 / 前序对不上）。

并提供可打印的**最小边界（矛盾）证书**：第三方只需该证书加一个常量大小的信任束，
无需整个原库，即可独立检出互相矛盾的两个边界。每个历史水位的结论都带哈希，可由封存
事实逐字节重复构建。

- 语言/平台：原生 Windows + Go（仅用 Go 1.20 起就具备的标准库能力；开发机实测 `go1.27.4 windows/amd64`）
- 依赖：**仅 Go 标准库**（Ed25519 封存用 `crypto/ed25519`，无第三方模块）
- 数据：全部本地确定性合成，无网络/外部服务

---

## 快速开始

在仓库根目录（含 `go.mod`）打开 PowerShell / cmd：

```bat
go test -count=1 ./...        :: 跑全部单元 + 穷举 + 局部扫描测试（或双击 test.cmd）
go run ./cmd/reviewer selftest :: 编译并运行内置验收自检（或双击 selftest.cmd）
go run ./cmd/reviewer demo     :: 生成三份副本、各水位报告、证书并做第三方复验（或 demo.cmd）
go build -o reviewer.exe ./cmd/reviewer   :: 构建原生 exe（或 build.cmd）
```

`demo` 默认把报告/证书写到 `artifacts/demo/`（该目录被 `.gitignore` 忽略）。
仓库另在 [`examples/`](examples/) 放了一份真实运行输出与证书样例，便于不运行也能核对。

单独做第三方证书验证（不需要原库）：

```bat
go run ./cmd/reviewer verify-cert --cert artifacts/demo/conflict-cert-wm7.json ^
    --trust artifacts/demo/trust-bundle.json
:: 不给 --trust 时仍做纯结构矛盾检出，只是不校验签名真实性
```

大数据比较次数基准：

```bat
go test -bench=. -run=^$ ./internal/segment/
```

---

## 核心模型与判定规则

| 概念 | 类型 | 说明 |
|---|---|---|
| 摘要 | `model.Digest` | SHA-256，带域分隔与长度前缀的规范编码 |
| 边界 | `model.Boundary` | `{Partition, Seq, Prev(前序摘要), Nonce, HandoffID}`，自有 `ID()` |
| 封存 | `SealedBoundary/Handoff/Revocation` | 叠加签名者与 Ed25519 签名，三份副本即此类记录 |
| 受信起点 | `model.Anchor` | 带外钉死的创世边界摘要，复核从这里向前接 |
| 交接记录 | `model.Handoff` | 授权某条“经交接进入本分区”的边界；可被撤销 |
| 有效撤销 | `model.Revocation` | 签名有效、指向已知交接、由交接 Owner 签发、且签发序号更晚才生效 |

**可采纳性（admissibility）**：没有 `HandoffID` 的边界凭其有效封存即采纳；带
`HandoffID` 的边界，仅当该交接存在、**未被有效撤销**、且其背书的坐标与 `FromDigest`
确实等于该边界的 `(分区,序号,Prev)` 时才采纳。伪造/越权/时序不对的撤销会被列入
`RejectedRevocations`，不改变结论。

**最长前缀走查**（`reconcile.Reviewer.Review(watermark)`）：从锚点提示摘要出发，按连续
序号逐格取“已采纳且 `Prev==当前tip`”的边界——

- 恰有 1 条：唯一接出，继续；
- 该坐标有 ≥2 个不同内容的边界：**已证冲突**，安全前缀停在其前一格；
- 否则 0 条可接（整段缺失，或唯一一条前序对不上）：进入**未证区间**。

**最早已证冲突**在整个水位窗口内独立扫描，因此即使前面隔着缺段，也能报告缺段之后的
冲突。**未证区间**由 `(可信末尾, 水位]` 中除去所有“已证冲突点”后的极大连续段构成，与
冲突点互不重叠、并对每个序号形成恰好一种分类（测试中有覆盖性断言）。

矛盾谓词正是题面所述：

```go
reconcile.Contradictory(a, b) ≡ 同 Partition && 同 Seq && a.ID()!=b.ID() && a.Prev!=b.Prev
```

同一坐标、同一 `Prev` 但不同内容体也算 equivocation（`SAME_PREV_DISTINCT_BODY`），
安全前缀同样不强行二选一；证书会如实标注是“前序摘要冲突”还是“同前驱异内容”。

---

## 最小边界证书与第三方验证

`reconcile.ConflictCert` 只包含：锚点、**互相矛盾的 A/B 两条已封存边界**，以及仅当 A/B
引用了交接时才附带的那几条交接/撤销上下文（普通矛盾对的 `handoffs` 为空）。样例
[`examples/sample-conflict-cert.json`](examples/sample-conflict-cert.json) 仅约 1.4 KB。

第三方 `reconcile.VerifyConflictCert(cert, ring)`：

1. 重算证书自哈希，发现篡改/损坏；
2. `DetectPair` 无库结构检出“同坐标、不同前序”的一对；
3. 若给了常量信任束 `model.KeyRing`：校验 A/B 与上下文的全部 Ed25519 签名，重放
   `EffectiveRevocations`，独立判定两条边界当前是否都可采纳。

只给证书、`ring=nil` 时做纯结构检出（人工核对场景）；给信任束时任何改内容后重算哈希
的篡改仍会因签名失效被拒（有专门的篡改测试）。信任束只有若干签名者公钥 + 锚点，是常量
大小，**不是原库**。

---

## 可重复构建的历史水位结论

`Report` 的每个切片都已排序、无 map 迭代泄漏、无时间戳/随机数；`ConclusionHash` 是对
“哈希字段留空后的规范 JSON”求域分隔 SHA-256。同一 `Facts` 任意次 `Review(wm)`、或把
`Facts` 序列化成 JSON 再反序列化重建，各历史水位 `{3,4,6,7,8,10}` 的哈希与整份 JSON 都
逐字节一致（见 `reconcile/repro_test.go`、`synth/world_test.go`、`verify.checkHistory`）。

---

## 穷举小图：插入、撤回、任意输入顺序

`internal/reconcile/exhaustive_test.go` 不依赖密码学，直接对纯内核做穷举：

- `TestExhaustiveCoordinateStates`：长度 L=1..4 的链，每个序号穷举
  `{缺失, 唯一正确, 单条错前序, 正确+分叉}` 四态，共 **4+16+64+256 = 340 个配置**。
  每个配置都：
  - 与一个**独立编写的参考 oracle** 比对可信末尾/状态/冲突序号/未证区间；
  - 跑一组强不变量（前缀是合法哈希链、前缀最大、状态自洽、冲突与直接两两扫描一致、
    窗口内每格“可信/冲突/未证”恰好一种分类）；
  - 有冲突就构造并验证结构证书；
  - op 数 ≤6 时对该配置跑**全部 n! 种输入排列**比对结论哈希；op=8 时跑恒等/逆序/全部
    旋转/固定 LCG 扰动的确定性顺序扫描。
- `TestInsertWithdrawAllOrders`：一个 6 操作的“交接 + 门控边界 + 对立边界 + 有效撤回”
  微世界，穷举 **2⁶=64 个子集 × 每个子集的所有排列 = 1957 次**结算，结论哈希必须完全
  一致（证明与插入/撤回的到达顺序无关）。
- `TestRevocationSemantics` 钉死关键语义：交接有效时可接出；交接缺失/被有效撤销时退化为
  未证缺口；“门控边界 + 对立边界”本构成已证冲突，**撤销该交接使门控方失效后，冲突消解
  为未证区间**。

`selftest` 内还带一份等价的黑盒全排列检查（Heap 算法，1956 次；空集不计数）。

---

## 大数据：隔开的三个空档，补齐一个分区只扫有关段，并量出比较次数

`internal/segment` 维护 `分区 -> 按 Lo 排序的段切片` 索引，所有比较都经过 `Meter` 计数并
记录触及的分区/段：`SegmentProbeCompares`（索引二分探针）、`ItemKeyCompares`（
`分区,序号` 键比较）、`LinkCompares`（`Prev==ID` 哈希链接检查）。

`synth.NewDefaultLarge()` 确定性构造 **12 分区 × 96 段 × 64 边界 = 73 728 条**独立哈希链，
在三个不同分区、早/中/晚三个隔开的块位（第 24/48/72 段）各删一段形成**三个隔开的空档**。

`segment/locality_test.go` 断言（不是只打印）：

- 对任一档调用 `Store.VerifyFill`：只触及**该档所属分区一个分区**；
- 真正展开扫描的段恰好是 `{左衔接段, 补入段, 右衔接段}`，**≤3 个有关段**；
- 索引探针数为 `O(log 段数)`（实测 7 次），并远小于跨全部 1149 段的全局裸扫基线；
- 补齐该分区后 `ReconstructPartition` 缺口消失、记录数正确，且仍只触及该分区；另外两个
  空档原样保留。

真实测量（`go run ./cmd/reviewer large`，亦见 examples）：

```
规模: 12 分区 × 96 段 × 64 边界 = 73728 条; 移除3个隔开的段形成空档
空档0 p02 [1537..1600]: comparisons total=137 (segmentProbe=7 itemKey=65 link=65)
      partitionsTouched=[p02] scannedSegments=3
      probedSegments=7 | 全局裸扫比较≈2298 | 局部/全局=0.0596
空档1 p05 [3073..3136]: 同上，仅触及 p05
空档2 p08 [4609..4672]: 同上，仅触及 p08
```

137 次比较中有 128 次用于校验补入段自身的 64 条链及其与两个衔接口的链接；定位相关段只需
7 次二分探针。`BenchmarkLocalizedFill` 用 `b.ReportMetric(...,"comparisons/fill")` 输出比较数。

---

## 合成剧本如何覆盖题面三种异常

`synth.NewCanonicalWorld()`（分区 `acct`，seq 0 为受信创世）：

- **缺整段**：三份副本都没有 seq 5（真正无法补的段 → 未证区间 `[5,6]`）；`dc-central`
  还整片缺失 seq 2–3，但并集从其它副本恢复，所以水位 3/4 仍干净接出——体现“有的副本缺段”
  与“全库缺段”的差别。
- **同序号不同前序摘要**：seq 7 上 `node-a` 签了正确链、`node-b` 签了指向另一历史的分叉，
  二者签名都有效 → 最早已证冲突 `seq7/PREDECESSOR_MISMATCH`。
- **交接后来被有效撤销**：`ho-acct-9` 授权 seq 9 门控边界，Owner `node-handoff` 在更晚
  签发有效撤销 → 该交接与门控边界失效；另有一个 `node-b` 越权撤销 `ho-acct-10`，签名有效
  但授权不符，被拒绝，`ho-acct-10` 继续有效。

真实运行结论表：

```
水位  状态                        可信到  最早冲突
3    REACHED_WATERMARK           3       -
4    REACHED_WATERMARK           4       -
6    BLOCKED_BY_UNPROVEN_GAP     4       -                 （只有未证区间 [5,6]）
7    BLOCKED_BY_UNPROVEN_GAP     4       seq7/PREDECESSOR_MISMATCH
8/10 同上（最早冲突恒为 seq7，未证区间按冲突点切分）
```

水位 7 同时给出：最长前缀可信到 seq 4、紧邻未证区间 `[5,6]`、最早已证冲突 seq 7，三者分离。

---

## 目录结构

```
go.mod                     模块 reviewer12731（仅标准库）
cmd/reviewer/main.go       Windows 原生命令：selftest/demo/verify-cert/large
internal/model/            摘要、边界/交接/撤销/锚点、Ed25519 封存与信任束
internal/stable/           确定性 JSON
internal/reconcile/        纯内核：结算、最长前缀、冲突/未证区间、结论哈希、最小证书+独立验证
internal/segment/          分区段索引、比较计数 Meter、局部补齐校验、分区重建、全局基线
internal/synth/            三份封存副本剧本 + 大三空档夹具（确定性密钥/数据）
internal/demo/             可测试的 demo 编排与“从磁盘第三方复验”
internal/verify/           可被 reviewer selftest 调用的黑盒验收自检
*_test.go                  穷举/oracle/不变量/证书篡改/可复现/局部扫描/端到端
examples/                  真实运行输出与证书样例
*.cmd                      test/selftest/demo/build 的 Windows 一键脚本
```

## 设计取向与边界

- 内核**不做密码学**：只处理已认证的纯事实，保证穷举跑得快、推理简单；签名/授权集中在
  `model` 认证层，认证后的“有效撤销”才进入内核。两层各有测试（含伪造/越权撤销）。
- 序号按“每分区连续递增”建模，这是哈希链日志的标准约束；交接记录负责分区流转的授权。
- 报告刻意保守：只要某格出现两个不同的有效主张就不替人选择正统，避免在拜占庭分叉上
  “接出”一个看似更长、实则不可信的前缀。
