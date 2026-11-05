# ChainBreak：面向 MCP 跨服务器调用链的组合安全形式化建模与模型检测
## 研究计划（v0.1，仅规划，不含实现）

> 工作名 **ChainBreak**，是对 A2ABreak 方法谱系的延续。目标：把"A2ABreak 式"的
> **规格形式化 → 自动机构建 → 漏洞模式检测 → 对抗验证** 迁移到 MCP，但检测对象从
> "单协议状态机"上升为"**多 MCP 服务器组合下的能力-效果自动机**"。

---

## 0. 一句话目标

给定一个真实 MCP 部署（客户端 + N 个服务器 + 宿主策略 + 共享外部状态），
自动构造其**组合自动机**，并用**漏洞模式自动机**做模型检测，
输出"在全合规假设下仍然成立"的**跨服务器攻击链见证（witness trace）**及严重性。

---

## 1. 关键判断：为什么不能直接搬 A2ABreak

这是整个计划的立论基础，必须先讲清楚。三条理由：

### 1.1 MCP 规范的安全相关状态太薄

A2ABreak 的输入是一份 929 条形式化语句的 A2A 规范（37 状态 / 76 迁移），
安全相关语义密集在**发现、认证、委派、任务生命周期**上——单协议 FSM 本身就是
有意义的攻击面。

MCP 规范不是这样。它的大部分内容是 JSON-RPC 消息格式、传输（stdio / Streamable HTTP）、
能力协商、分页、进度、取消。把 MCP 规范整篇抽成 FSM，得到的会是一个**小而安全无聊**的
自动机，主要覆盖 `server/discover`、授权发现（OAuth 元数据、client registration、
audience 校验）和工具/资源/提示的 CRUD 流程。直接套用几乎必然得出"A2ABreak 在 MCP 上找不到东西"
的错误结论。

### 1.2 真正的攻击面在组合与宿主策略，而不在服务器内部

MCP 的漏洞来自"A 服务器的**输出**改变了 LLM 对 B 服务器的**调用**"。
协议在消息层面完全合规——每个服务器都按自己的契约行事——危险来自**没有任何一方负责的跨边界语义**。
这正是 [AgentThread](https://arxiv.org/abs/2606.28690) 所称的 "responsibility gap"，
也是 [Five Hops Through MCP](https://zenodo.org/records/22781075) 用纯协议手段串起
"filesystem 作用域替换 → 审批绕过 → memory 共享图投毒 → 跨客户端指令转移 → 自我续写"
五个跳转的原因。

所以组合模型必须显式包含三个在 MCP 规范里**不存在**的东西：
1. **宿主/客户端中介策略**（审批表、roots 白名单、工具名归一化、采样策略）；
2. **共享外部状态**（文件系统、memory 图、数据库、凭证存储）；
3. **上下文与来源标注（provenance）**——以及它的**缺失**。

### 1.3 2026-07-28 版把状态从协议里移除了

最新规范（2026-07-28）**删除了 `initialize` 握手与 `Mcp-Session-Id`**，
改为无状态、每请求在 `_meta` 里携带 `protocolVersion` / `clientCapabilities`；
`ping`、`logging/setLevel`、`roots/list_changed` 被删除；
`resources/subscribe` 换成了 `subscriptions/listen`；
tasks 移出核心成为扩展。跨调用状态改由"**服务器自己铸造的句柄作为普通工具参数**"传递
（SEP-2567），列表端点**不允许**随连接变化。

含义很直接：**"调用链"的状态不在协议里，而在句柄与外部存储里。**
一个不建模外部存储和无状态重入的自动机，连 Five Hops 的第 3 跳都表达不出来。

### 1.4 结论：迁移的是**方法**，不是**模型对象**

| 维度 | A2ABreak | ChainBreak |
|---|---|---|
| 形式化对象 | 单协议 FSM | 多服务器乘积 + 宿主策略 + 环境存储 |
| 状态载体 | 协议阶段 | 服务器内部状态 + 显式句柄 + 共享存储 + 上下文来源标签 |
| 对手模型 | 全合规协议参与者 | 全合规参与者 + 可被上下文内容使能的 LLM |
| 漏洞来源 | 协议设计缺口 | 组合责任缺口 + 策略实现缺口 |
| 输出 | 协议级漏洞 | 可回放的跨服务器攻击链见证 |

---

## 2. 形式化模型

### 2.1 抽象域（有限格）

工具参数与返回值不建具体模型，抽象为**来源-完整性-敏感度**三元格：

```
L = P × I × S
P (provenance) : 2^Principal     —— 谁"写过"这个值（用户 / 服务器 i / 外部不可信源 / 模型）
I (integrity)  : {trusted, untrusted, mixed}
S (sensitivity): {public, internal, secret}
```

关键点：**来源是一个集合，且会随组合而丢失**。形式化"丢失"：

```
ctx_add(v, l)  =  l                        // 标注已知时
ctx_add(v, ⊥)  =  (attacker-any, untrusted, unknown)   // 无标注 ⇒ 最坏假设
```

MCP 的共享存储（memory 图、文件、KV）以及 LLM 上下文**没有强制 provenance**，
因此模型里默认走第二支。这不是"保守假设"，而是 Five Hops 那类链条成立的**充要条件**——
把它写进语义，链条就能被自动推出来；不写，任何检测器都推不出来。

### 2.2 服务器能力转移系统（CTS）

每个服务器 `S_i` 建模为一个带效果签名的转移系统：

```
M_i = ( Q_i, q_i0, Act_i, →_i, lab_i )
Act_i = { list, call(t, a), ret(t, v), notify, sample, elicit, mint(h), use(h) }
lab_i : →_i → Eff
Eff   = ( R_D, W_D, X, N_D, A_s )     // 读域 / 写域 / 执行 / 网络出口 / 所需授权域
```

`R_D, W_D, N_D ⊆ DataDomain` 是数据域集合（`fs:home`、`mem:shared`、`net:any`、
`cred:ssh` 等）。工具的效果签名来自**三条互相独立的证据**：

- **声明（declared）**：`tools/list` 的 `description` + `inputSchema`/`outputSchema` + `annotations`
  （`readOnlyHint` / `destructiveHint` / `idempotentHint` / `openWorldHint`）；
- **推断（inferred）**：对实现（若可得）的静态分析，或对同类工具的规则推断；
- **观测（observed）**：运行时 JSON-RPC trace / OTel span 的进程挖掘结果。

三者**不一致本身就是一类漏洞**（见 P3、P8），所以不合并，作为模型的第三维保存。

> 规范明确说 annotations "应被视为不可信，除非来自可信服务器"，
> 而协议并不强制校验——[Trust Labels as Attack Surface](https://zenodo.org/records/23129666)
> 把这条"未强制执行的契约"系统化了。我们的模型把注解当作**声明**而非**事实**，这是设计上的硬约束。

### 2.3 环境与组合语义

```
Env  = ( Store, Context, Cred, Consent )
Store   : 命名共享存储的映射（每个存储带 provenance 策略声明 ∈ {enforced, absent}）
Context : LLM 上下文，元素带 L 标签
Cred    : 令牌/授权，带 audience 与 scope
Consent : 人类审批状态（审批键、绑定对象、有效期）
```

组合自动机：

```
A_comp = ( ⊗_{i=1..n} M_i )  ∥  ClientPolicy  ∥  Env
```

- `⊗` 为异步交错，**唯一的同步点是共享存储与上下文的读/写**；
- `ClientPolicy` 是部分函数 `decide(event, ctx) → {allow, deny, ask}`，
  内含审批表、roots 白名单、工具名归一化映射（这几个正是真实攻击的落点）；
- `Env` 的读/写迁移携带 L 标签的传播规则。

### 2.4 对手模型：全合规对手 + 上下文使能关系

A2ABreak 的核心假设是"对手遵守规范，漏洞依然存在"。MCP 需要再加一层，因为
**真正执行动作的是 LLM**。我们把 LLM 建模为**非确定性但受使能约束**的调度器：

```
Enable ⊆ Context × Act        // 使能关系：上下文中出现过对某动作的"指令"
enabled(a)  ⟺  ∃ e ∈ Context. (e, a) ∈ Enable  ∧  instr(a) ⊆ content(e)
```

即：**LLM 只会发起它"见过"的调用**。而"见过"取决于上下文里内容的来源。
于是跨服务器攻击被精确地刻画为：

> 不可信来源写入的内容 `e`，获得了对高效果动作 `a` 的**使能权**，
> 且 `a` 的效果触及被保护的数据域，全程无人类同意事件，且每一步协议合规。

这个 `Enable` 关系是整个模型的技术核心。它把"提示注入"从一句模糊描述，
变成一个可以在自动机上判定的关系，同时保持"对手不需要任何实现缺陷"这一 A2ABreak 式的强假设。

### 2.5 检测问题

- **存在性问题（模式匹配）**：`L(A_comp) ∩ L(B_p) ≠ ∅ ?` 且返回最短见证。
  其中 `B_p` 是模式 p 的**攻击自动机**（坏行为 NFA/Büchi）。
- **全称问题（不变式）**：`A_comp ⊨ φ`，φ 为 LTL/CTL 不变式（例如"任何标注为
  `enforced` 的存储，其写入必带 provenance"）。
- **缺省问题（责任缺口）**：`φ` 在 MCP 规范层面**无任何组件承担**——通过对每条
  MUST/SHOULD 义务做"承担者归属"分析得到，这是 P10 模式的来源。

**边界与可靠性口径**：在效果抽象采用 *may-summary*（过近似）时，报出的
"存在链"是**可靠的（sound）**；在采用 *must-summary* 时可判定"不存在链"。
k-跳有界搜索下，结论表述为"存在长度 ≤ k 的链"，并给 k 与抽象精度。

---

## 3. 漏洞模式库（攻击自动机）

模式不是手写正则，而是**参数化模板**：模板 = (事件骨架, 效果谓词, 跨服务器约束, 规范/实证锚点)。
实例化时才绑定具体服务器与数据域。

| ID | 名称 | 攻击自动机骨架 | 效果谓词 | 锚点 |
|---|---|---|---|---|
| P1 | 工具影子 / 命名空间碰撞 | `list(S_j)` 声明与 `t∈S_i` 同名（或归一化后同名）→ `call(S_j,t')` | 执行键 ≠ 策略键，且 `eff(S_j.t') ≻ eff(S_i.t)`，且无审批 | Invariant Labs 2025；Cline 修复不一致 |
| P2 | 跨服务器污点外泄（致命三要素） | `read_private(S_i)` → 值入 Context → `call(S_j, sink)` 参数含该值 | `N_D` 出口或外部写，携带 secret 标签，中途无 consent | lethal trifecta 文献 |
| P3 | 能力放大 / 注解谎报 | `list` 声明 `readOnlyHint=true` → `call` 产生 `W_D ≠ ∅` | `declared ≺ observed` | 规范"注解不可信"条款 |
| P4 | 句柄洗白 / confused deputy | `mint(h)@S_i` → `call(S_j, h)` → `use(h)@S_i` | 访问 `S_i` 资源时 audience/scope 不匹配 | SEP-2567 无状态句柄 |
| P5 | 共享状态持久化投毒 | `write(Store_shared, 不可信指令)` → 会话/进程重启 → `read@S_j` 入 Context | `Store` 的 provenance 策略 = absent，且跨会话存活 | Five Hops 第 3–5 跳 |
| P6 | 授权上下文塌缩 | `_meta` 能力/版本/身份伪造 → `call` 命中他服务器 scope | scope/audience 混淆或 token 透传 | 2026-07-28 无状态化 |
| P7 | 服务器发起的特性劫持 | `sample/elicit@S_i` 内容含指令 → 客户端委派到 `S_j` | 服务器撰写内容使能了 `S_j` 上的调用 | sampling/elicitation 语义 |
| P8 | TOCTOU / rug pull | `list@t0`（良性）→ 审批绑定名字 → `call@t1`（行为已变） | 审批绑定到 name 而非 schema 哈希/版本 | `tools/list_changed` |
| P9 | 取消与重入竞态 | MRTR 重入或 `cancel` 后 → 部分效果已提交 / 双重执行 | 效果在取消后仍落盘 | 多轮请求模式 |
| P10 | 责任缺口（元模式） | 存在不变式 `I` → 所有组件都不承担 `I` → 存在违反 `I` 的合规轨迹 | `I` 的承担者集合为空 | AgentThread 结论 |

P10 是元模式：它对任何"应当被强制但无人强制"的属性生成一个模式，
是抵御"我们只找到我们编码过的东西"这一批评的主要手段。

**模式的合法性约束**（避免自我循环论证）：
每个模式必须能追溯到 (a) 规范中的一条规范性语句，或 (b) 一份公开的真实报告。
不允许"为了发现而发明"的模式进入主库；这类探索性模式进 `patterns/experimental/`，单独报告。

---

## 4. 模型获取流水线（A2ABreak 阶段映射）

这是"迁移"的具体落点。原流水线基本保留，但**输入源从 1 个文档变成 4 类证据**。

| A2ABreak | ChainBreak 对应 | 关键变化 |
|---|---|---|
| A1 结构抽取 | MCP 规范**按特性页**（tools / resources / prompts / roots / sampling / elicitation / auth / subscriptions / discover / tasks）分别抽取状态与约束 | 1 文档 → 约 10 个特性页；语义单位从"回合"变"无状态请求" |
| A2 行为抽取（RFC 2119 → 迁移） | 同上；且把 **SHOULD 单独收集**为"义务候选"（P10 的原料） | MUST→迁移，SHOULD→责任缺口候选 |
| Merge + Verify | 保留；增加与 `schema.ts` 的**机械对账**（方法名、字段名必须存在于 schema） | 降低幻觉率的主要闸门 |
| B1 过滤 + 六阶段 | 改为按**能力域**分层：discovery / auth / invoke / server-initiated / persistence / termination | MCP 没有 A2A 的六阶段 |
| B2 每阶段 FSM | 每个服务器生成 **CTS**（含效果签名） | 从"协议 FSM"升级为"能力转移系统" |
| B3 跨阶段迁移 | **跨服务器组合边发现**：共享存储、句柄传递、上下文使能 | **全新的核心步骤**，必须被发现而非假设 |
| B4 统一 FSM | 乘积构造 `A_comp` | 引入锥化与抽象以对抗状态爆炸 |
| D1/D2 清理与去重 | 保留 + **抽象等价类合并**（同效果签名的工具合并） | 组合场景下必要 |
| C1 漏洞搜索 | 双轨：**模式驱动**（P1–P10 求交）+ **差异驱动**（声明 vs 观测的契约违背挖掘） | 后者是发现新漏洞的主要来源 |
| C2 对抗验证 | 保留：合规性判定 + 规范性规则 + 严重性；**新增：对真实服务器回放见证** | 模型-现实差距的最终裁决 |
| zero-shot 基线 | 保留 | 复现"A2ABreak 零样本 0 条确认"的对照结论 |
| formal_verification（Alloy/TLA⁺） | 直接复用：把 `A_comp` 与不变式发射为 TLA⁺/Promela | 交叉验证引擎 |

### 4.1 跨服务器组合边的发现（B3'，最难的一步）

这是整个流水线里唯一**没有现成方法可抄**的环节。三条证据路径：

1. **静态**：类型/签名匹配——A 的输出 schema 与 B 的输入 schema 存在结构可对接性；
   若 B 的参数名/格式形如 `handle`、`id`、`uri`、`path`，且 A 有此输出，则建立候选边。
2. **语义**：LLM 对"这个工具的输出会被哪个工具消费"做判断，必须在候选边上给出**引用证据**
   （取自 description / 示例 / 文档），并进入人工抽检集。
3. **动态**：trace 中同一值（或其指纹）出现在 A 的返回值与 B 的参数中 ⇒ **实证边**。

静态/语义边给"可能存在"，动态边给"确实发生"。检测报告必须标注边的证据等级，
否则工具会退化成"猜链子"。

---

## 5. 检测引擎

### 5.1 架构选择

| 层 | 方案 | 理由 |
|---|---|---|
| 内部 IR | JSON（`model/ir.schema.json`），与形式化定义一一对应 | 所有前端的唯一交换格式，可人工审查 |
| 主引擎 | **自研显式状态搜索**（k-有界 + 迭代加深 + 偏序归约） | 见证质量（可读 trace）是产品的核心，不能依赖外部工具的输出格式 |
| 交叉验证 | 发射 **Promela → SPIN**（存在性 + LTL）；发射 **TLA⁺ → TLC**（不变式） | 与既有工作可比；用不同算法交叉确认 |
| 参数敏感 | **SMT（Z3）有界模型检测**，仅在效果谓词涉及路径/URL/scope 时启用 | 抽象会丢掉的约束在这里补回 |

### 5.2 状态爆炸的控制

乘积的朴素规模是 `∏|Q_i|`，必须做五件事：

1. **锥化（cone of influence）**：按模式 p 的效果域，只纳入能触及该域的服务器；
   不做全局乘积，做**查询驱动的按需乘积**。
2. **效果摘要**：工具调用的参数以抽象标签代替具体值；同效果签名的工具合并为一个抽象动作。
3. **对称约简**：结构同构的服务器（如多个同类 storage server）折叠。
4. **k-有界 + 迭代加深**：先 k=3（大多数真实链条 ≤5），再按需加深；
   报告中明确 k。
5. **偏序归约**：跨服务器动作大多独立，仅共享存储/上下文的读写需要保序。

**规模预期**：n=5、每服务器 8–12 状态、k=5 时，锥化后单查询应在 10^4–10^5 量级，
秒级可完成。这是需要在 Phase 2 末尾实测验证的关键假设。

### 5.3 见证（witness）的定义与验证

见证 = 有序事件序列，每个事件含：服务器、方法、参数抽象、此时的效果、Context/Store 的
标签变化、策略判定、必要时的具体参数实例。

C2 式对抗验证对每个见证回答四个问题：
1. **合规性**：每一步是否满足规范（无未定义行为、无越权消息）？
2. **可达性**：在模型里确实可达（不是抽象引入的假象）？
3. **可实例化**：能把抽象标签落实为具体参数/内容吗？
4. **严重性**：影响哪些数据域、是否需要用户交互、是否跨会话存活？

加分项（Phase 3 之后）：**真实回放**——用 MCP SDK/Inspector harness 对
沙箱内的服务器重放见证。回放成功 → 证据等级最高。

---

## 6. 工具架构与仓库布局

```
MCPserver/
  docs/
    PLAN.md                 # 本文件
    FORMALISM.md            # 形式化定义（格、CTS、组合语义、Enable 关系）
    PATTERNS.md             # 模式库规格与合法性约束
    THREAT-MODEL.md         # 对手模型、信任边界、假设与不假设
  model/        ir.schema.json, lattice.py, cts.py, product.py
  acquire/      spec/（规范特性页抽取 + 校验）, manifest/（注解→效果）, trace/（挖掘）, reconcile/
  compose/      env.py, policy.py, cone.py, abstraction.py
  patterns/     dsl/, instances/P1..P10, experimental/
  check/        native/（显式状态 + 见证）, emit_promela.py, emit_tla.py, smt/
  verify/       compliance.py, instantiate.py, replay/（真实服务器回放）, severity.py
  eval/         corpus/, groundtruth/, baselines/, metrics/, reproduce.sh
  report/       json/, sarif/, markdown/
```

**设计原则**：每一层都能独立产出可审查工件（IR JSON、见证 JSON、报告），
不追求"一条命令出结论"，追求"结论可被逐层质疑"。这是安全工具可信度的前提。

---

## 7. 路线图与验收门槛

| 阶段 | 周 | 产出 | 验收门槛（Gate） |
|---|---|---|---|
| **P0 形式化与手工金丝雀** | 1–2 | `FORMALISM.md` 定稿；手工建模 filesystem + memory 两个服务器 | **G0**：手工模型能自动推出 Five Hops 的 5 跳链，且每步合规 |
| **P1 模型获取** | 3–6 | 规范→CTS；manifest→效果签名；IR；注解信任轴 | **G1**：10 个真实服务器 manifest 自动转 CTS，人工抽检准确率 ≥ 90%；覆盖 8 个协议特性 |
| **P2 组合与检测** | 7–10 | 乘积 + 环境 + 策略 DSL；原生引擎；P1/P2/P5 | **G2**：canary 上自动发现 5 跳链；2 个已知案例召回；单查询 ≤ 60s |
| **P3 模式扩展与验证** | 11–13 | P3/P4/P6/P7/P8/P10；对抗验证器；SPIN/TLA⁺ 发射；消融 | **G3**：10 模式全部可实例化；见证可实例化率 ≥ 80%；与 SPIN 交叉验证一致 |
| **P4 评测与写作** | 14–16 | 30 个多服务器部署语料；ground truth；4 条 RQ；基线对比 | **G4**：precision ≥ 75%（专家复核）、recall 报告齐备、新颖性声明可辩护 |

**建议的关键路径风险**：G0 是整个计划的"可行性判据"。如果手工模型都推不出已知链条，
说明形式化选错了抽象层次，必须在第 2 周结束前推翻重来，而不是继续往下建。

---

## 8. 评测设计

### 8.1 语料

- **已知链条集（ground truth）**：Five Hops（filesystem+memory+Cline）、
  Invariant Labs 的跨服务器 shadowing、Cymulate EscapeRoute（CVE-2025-53109/53110）、
  oddguan 的 memory server 利用。这些提供"必须检出"的下界。
- **真实部署集**：从 MCP registry / 公开 `mcp.json` 配置里取 30 个"多服务器 + 常见客户端"的组合。
  每个部署构造 manifest 快照 + 策略配置 + 存储拓扑。
- **合成集**：按参数化生成器构造 N 服务器组合，用于规模与召回的可控实验。

### 8.2 研究问题

- **RQ1（可迁移性）**：组合自动机能否在**不编码攻击**的前提下复现已知跨服务器链条？
  → 度量：已知链条召回率、平均检出跳数、假链数。
- **RQ2（精确性）**：专家复核下的精确率/F1（对标 A2ABreak 的 73.3% / 84.6%）。
- **RQ3（形式化的价值）**：与零样本 LLM 基线对比（A2ABreak 的基线产出 0 条确认发现，
  这是一个很有力的对照）；与 per-server-only 消融对比（丢掉多少组合发现）。
- **RQ4（规模）**：状态空间与时间随 n、k 的增长；抽象比率；锥化收益。
- **RQ5（新发现）**：在真实部署上是否找到此前未报告的问题（负责任披露流程见 §10）。

### 8.3 必须做的消融

| 消融 | 检验的假设 |
|---|---|
| 去掉 Context 的 provenance 建模 | 跨服务器链是否完全消失（若是 → 证明 provenance 缺失是核心机制） |
| 去掉宿主策略模型 | 检出率下降多少（量化"责任在客户端"的程度） |
| 注解当作事实（而非声明） | P3/P8 是否归零 |
| 只建单服务器模型 | 组合增量的量化 |
| 静态边 vs 静态+动态边 | 组合边发现方法的边际收益 |

### 8.4 基线

1. 零样本 LLM（A2ABreak 式，直接喂 manifest）；
2. per-server 静态扫描（mcp-scan / mcp-server-lint 一类）；
3. MCPSHIELD 式 LTS + 信任边界标注，**但不带模式库**（检验"模式库本身贡献多少"）；
4. AgentThread 式 TLA⁺ 不变式（检验"存在性模式 vs 全称不变式"的分工）。

---

## 9. 风险与对策

| 风险 | 说明 | 对策 |
|---|---|---|
| **R1 模型-现实差距**（最大） | 抽象掉了参数，可能"纸上谈兵" | 见证必须可实例化；Phase 3 起做真实回放；报告标注证据等级 |
| **R2 LLM 抽取幻觉** | 规范抽取凭空造出迁移 | 复用 A2ABreak 的 Verify 阶段；增加与 `schema.ts` 的机械对账；每条语句必须带原文引用；抽检集 |
| **R3 状态爆炸** | 乘积不可控 | 锥化 + 效果摘要 + k-有界 + 偏序归约；G2 设定 60s 硬门槛，超时即视为设计问题 |
| **R4 模式库循环论证** | "只找到编码过的东西" | 模式须有规范/实证锚点；P10 元模式；差异驱动挖掘；实验性模式单独报告 |
| **R5 真实服务器回放的伦理/法律** | 不能对他人系统做破坏性测试 | 只用自有/沙箱服务器；只调只读与无副作用方法；披露流程先行 |
| **R6 规范版本漂移** | 2025-11-25（有会话）与 2026-07-28（无状态）并存，生态大量仍是旧版 | 把"协议纪元"作为模型参数，两版都支持；默认按部署实测版本 |

---

## 10. 与已有工作的差异（需要写进论文的相关工作表）

| 工作 | 对象 | 形式化 | 组合 | 检测方式 | 与本计划的差异 |
|---|---|---|---|---|---|
| [A2ABreak](https://arxiv.org/abs/2609.10871) | A2A 单协议 | 规范抽取 FSM | ✗ | LLM 搜索 + 对抗验证 | 我们迁移其方法，但对象是多服务器组合，且模型必须含外部存储与 provenance |
| [AgentThread](https://arxiv.org/abs/2606.28690) | 5 个 agent 协议 | TLA⁺ 不变式 | ✓（协议级） | 模型检测 + SDK 回放 | 它是**全称不变式**、协议级责任归属；我们是**存在性攻击链**、服务器级组合语义 |
| [MCPSHIELD](https://arxiv.org/abs/2604.05969) | MCP | 带信任边界的 LTS | 部分 | 分类学 + 防御 | 它是威胁分类与防御架构；我们是可执行的检测器 + 见证 |
| [Five Hops](https://zenodo.org/records/22781075) | MCP 实证 | ✗ | ✓（案例） | 手工 | 我们提供**自动**发现同类链条的形式化机制；它反过来是我们的 ground truth |
| [MCP-SafetyBench](https://arxiv.org/abs/2512.15163) | MCP 数据集 | ✗ | ✗ | 基准评测 | 模型级安全评测；可复用其服务器语料，但不解决组合形式化 |

**新颖性主张（三条）**：
1. 首个把 MCP 安全检测建立在"**多服务器乘积 + 宿主策略 + 共享存储 + 上下文 provenance**"
   之上的组合形式化模型，并给出全合规对手下的可靠性口径。
2. **上下文使能关系（Enable）**：把提示注入刻画为自动机上可判定的关系，
   而非自然语言描述——这是让"存在性攻击链"可被模型检测的关键。
3. **模式化 + 差异化的双轨检测**与**可实例化见证**的端到端流水线，
   把 A2ABreak 的"规范驱动"扩展为"规格 × 部署 × 观测"三源驱动。

---

## 11. 需要你现在决定的三件事

1. **目标形态**：偏"可发表的研究"（RQ 与基线优先），还是偏"能用的工具"
   （部署接入、CI、报告格式优先）？两者的 Phase 3–4 取舍不同。
2. **模型获取的边界**：只做**静态**（规范 + manifest + 策略配置，零侵入，可规模化）
   还是**静态 + 运行时 trace**（召回更高，但需要接入真实客户端、有数据获取成本）？
   建议：P0–P2 只做静态，P3 引入 trace 作为可选增强。
3. **实现语言**：Python（与 A2ABreak 的生态、LLM 工具链一致，最快出结果），
   还是 Rust/TypeScript（与 MCP SDK 生态更近，工具化更好）？
   建议：Python 做模型与检测，见证回放用 TypeScript（官方 SDK）。

---

## 12. 立即可做的第一步（不含代码）

在 `docs/FORMALISM.md` 里完成 §2 的完整定义（格、传播规则、CTS、组合语义、Enable、
检测问题、可靠性口径），并**手写**一个 filesystem + memory 的 2 服务器模型（JSON），
在纸上验证 Five Hops 的 5 跳能否被表示。这一步不写检测器，
只回答一个问题：**这个抽象层次够不够表达真实链条。** 不够，就换。

---

## 参考

- A2ABreak 仓库：https://github.com/arlotfi79/A2ABreak ｜ 论文：https://arxiv.org/abs/2609.10871
- AgentThread（协议组合，TLA⁺）：https://arxiv.org/abs/2606.28690
- MCPSHIELD（MCP 形式化框架）：https://arxiv.org/abs/2604.05969
- Five Hops Through MCP（跨服务器实证链）：https://zenodo.org/records/22781075
- MCP-SafetyBench：https://arxiv.org/abs/2512.15163
- Trust Labels as Attack Surface（注解契约）：https://zenodo.org/records/23129666
- MCP 规范 2026-07-28：https://modelcontextprotocol.io/specification/2026-07-28
- Invariant Labs 工具投毒：https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
