# 对比：`MCP/mcpsec` 与 `chainbreak`

两份实现都是"MCP 跨服务器组合安全 + 模型检查"，但建模精度和结论强度不同。
本文只做技术对比，结论可直接用于选型与答辩准备。

---

## 1. 一句话概括

| | 做法 | 强项 | 短板 |
|---|---|---|---|
| **mcpsec** | 客户端 + N 台服务器做同步积，共享上下文是几个布尔变量，属性是边上的谓词 | 结构极简（534 行）、JSON 声明式规范、有 NuSMV 导出、开题文档 RQ1–RQ6 完整 | 服务器无状态、无数据流、无注入通道；组合性主张有一处站不住 |
| **chainbreak** | 组合图 = 各服务器 EFSM × 上下文 × 共享存储，三类边，标签格，三态判定 | 有服务器状态、有标签与来源、三条通道、可区分"局部缺陷/组合漏洞"、穷尽性可证 | 代码量更大（约 1300 行）、抽象仍粗、无真实服务器回放 |

---

## 2. `mcpsec` 里发现的四个实质问题

以下每条都实际跑过验证，不是读代码猜的。

### 2.1 主演示里有一条"违例"不是组合产生的

`main.py` 报告两条违例，其中：

```
• 属性 confused_deputy
  攻击迹 : call:B:export          ← 长度 1，只涉及服务器 B
```

把 A、C 从 `servers.json` 里删掉，只留 B，这条违例**依然存在**：

```
noA.json    -> [('confused_deputy', ['call:B:export'])]
onlyB.json  -> [('confused_deputy', ['call:B:export'])]
```

这直接冲击"单台安全 ≠ 组合安全"的主张：审稿人只要问一句"这条单台也能复现，凭什么是组合漏洞"，
主演示就站不住。

**chainbreak 的处理**：每条发现自动标注**局部缺陷 / 组合漏洞**——把见证里出现的服务器逐个单独跑一遍，
单台能复现就标"局部"。场景 09（影子工具）就是这样被自动标成局部的。

### 2.2 NuSMV 导出是坏的，无法被 NuSMV 解析

`nusmv_export.py` 里 `bad` 集合装的是**状态键**（嵌套元组），写进模型时却直接插值：

```
VAR state : 0..3;
...
DEFINE bad := case
  state = ((('A','idle'),('B','idle'),('C','idle'),('client','selecting')),
           (('authorized',True),...)) : TRUE;
```

`state` 声明的域是整数 `0..3`，却拿元组去比较。这份 `.smv` 一行 NuSMV 都跑不了，
所以 README 里"用 `NuSMV out.smv` 复验 CTLSPEC"的承诺是未验证的。

**chainbreak 的处理**：导出为 `state = <整数下标>`，用 `ASSIGN next(state) := case ... esac`
给出转移关系，`DEFINE bad := state = 3 | state = 7;`，性质 `CTLSPEC AG !bad;`。

### 2.3 状态数超限时静默报"未发现违例"

```python
if nk not in states:
    states[nk] = ...
    if len(states) <= max_states:   # 超了就停止扩展
        queue.append(nk)
```

`reachable()` 没有返回"是否被截断"，`model_check()` 于是走 else 分支打印
`[OK] 在已探索的状态空间内未发现属性违例`。

对一个**以证明不存在为目标**的工具，把"没搜完"报成"安全"是可靠性缺陷。

**chainbreak 的处理**：三态判定——`UNSAFE`（有见证）/ `SAFE`（穷尽且无反例）/
`UNKNOWN`（触达上限）。有专门测试 `test_truncated_search_is_unknown_not_safe` 锁住。

### 2.4 服务器没有状态，因此表达不了真实链条

`spec.py` 给每台服务器生成的是：

```python
server_trans = {"idle": [(label, "idle")]}   # 单状态 + 自环
```

没有 EFSM、没有句柄、没有游标、没有"写进共享目录再被另一台读出"。
共享上下文只有 `secret_in_context / user_consent / authorized / exfiltrated` 四个布尔。

后果：
- **A 读 → B 写 → C 发**（文件系统中介）表达不出来，因为没有"共享介质"这个对象；
- **search 恶意页面 → upload .env** 表达不出来，因为 `untrusted` 是**服务器**的静态集合，
  不是**内容**的来源；模型里没有"外部内容进入上下文"这个通道；
- `tool_def_version` 在文档里写了（rug-pull 检测），代码里没有。

**chainbreak 的处理**：服务器有 EFSM 状态；共享存储是一等对象；三条通道
（参数边 / 上下文边 / 存储边）显式建模。

---

## 3. 从 `mcpsec` 借鉴过来的三样东西

| 借鉴点 | 落地 |
|---|---|
| **声明式 JSON 规范**，加场景不改代码 | `scenarios/*.json`，支持引用内置部署或内联定义（场景 10） |
| **NuSMV 导出**，让外部模型检查器独立复验 | `chainbreak/nusmv.py`（修好了下标 bug） |
| **单命令端到端** | `python3 deliver.py`，控制台报告 + `report.md` + `reports/*.smv` |

`mcpsec` 的开题文档（RQ1–RQ6、基线、指标、里程碑）写得很好，建议**保留原样**作为论文提案，
本文只补建模层的差异。

---

## 4. 维度对比

| 维度 | mcpsec | chainbreak |
|---|---|---|
| 服务器状态 | 单状态自环 | EFSM（资源/句柄/授权/存储四种原型） |
| 共享上下文 | 4 个布尔 | 标签格 `来源×完整性×敏感度×权限域` |
| 通道 | 仅参数（隐含） | 参数 / 上下文 / 存储，三条显式 |
| 注入通道 | 无 | 有（F7，控制层属性） |
| 跨服务器分享介质 | 无 | 有（`Deployment.shared`） |
| 判定 | 二态（发现/未发现） | 三态（UNSAFE / SAFE / UNKNOWN） |
| 截断处理 | 静默报 OK | 报 UNKNOWN |
| 局部 vs 组合 | 不区分 | 自动标注 |
| 外部复验 | NuSMV 导出（不可解析） | NuSMV 导出（可用） |
| 场景扩展 | 改 JSON | 改 JSON |
| 代码量 | 534 行 | 约 1300 行 |
| 真实服务器回放 | 无 | 无（下一步） |

---

## 5. 建议的合并方式

1. **保留 `mcpsec` 的开题文档**作为研究提案（RQ 与实验设计都可直接用）；
2. **用 `chainbreak` 当建模与判定引擎**（状态、标签、通道、三态）；
3. **用 `scenarios/` 承载全部演示用例**，答辩时现场加一个 JSON 就能演示扩展；
4. **NuSMV 导出统一用 chainbreak 的版本**，把 `mcpsec/out.smv` 换掉；
5. 下一步：把 3 个场景的真实 MCP 服务器（官方 filesystem / memory / fetch）接上，
   做见证回放——这是两份实现目前都缺的、也是最有分量的一块。
