# ChainBreak 判定报告

> 自动化生成。安全属性 G 的判定结果：UNSAFE 有见证，SAFE 为状态空间穷尽后的证明。

| 编号 | 场景 | 部署 | 策略 | 判定 | 期望 | 状态数 |
|---|---|---|---|---|---|---|
| 01 | search 恶意页面 → 诱导 upload 传走 .env | INJECT | naive | **UNSAFE** | unsafe | 21 |
| 02 | search 单独运行 | INJECT | naive | **SAFE** | safe | 5 |
| 03 | envfs 单独运行 | INJECT | naive | **SAFE** | safe | 4 |
| 04 | upload 单独运行 | INJECT | naive | **SAFE** | safe | 2 |
| 05 | 防御：只做数据标签（敏感不外发） | INJECT | data-only | **UNSAFE** | unsafe | 21 |
| 06 | 防御：只做影响污点（不可信在场不外发） | INJECT | influence-only | **UNSAFE** | unsafe | 17 |
| 07 | 防御：数据标签 + 影响污点 | INJECT | hardened | **SAFE** | safe | 17 |
| 08 | A 读 → B 写 → C 发（共享存储通道） | ABC | naive | **UNSAFE** | unsafe | 22 |
| 09 | 影子工具：声明只读、实测外发 | MAIN | naive | **UNSAFE** | unsafe | 4418 |
| 10 | 内联自定义部署（演示可扩展性） | CUSTOM | naive | **UNSAFE** | unsafe | 8 |

共 10 个场景，期望不符 0 个，耗时 2300 ms。

## 发现

### 01 · search 恶意页面 → 诱导 upload 传走 .env

- 策略：`naive`
- 备注：完整三跳链；最后一步同时违反数据属性 F1 与控制属性 F7
- **[F1] 敏感数据外泄** — 组合漏洞
  - 链路：`search.search → envfs.read_file → upload.upload`
  - 依据：upload.upload 把「user/trusted/secret/self」经调用参数/上下文发往网络出口
- **[F7] 注入驱动外联** — 组合漏洞
  - 链路：`search.search → envfs.read_file → upload.upload`
  - 依据：上下文含不可信内容时执行外发：upload.upload

### 05 · 防御：只做数据标签（敏感不外发）

- 策略：`data-only`
- 备注：挡住 F1，但挡不住「上传非敏感内容到恶意地址」→ F7 仍在
- **[F7] 注入驱动外联** — 组合漏洞
  - 链路：`search.search → upload.upload`
  - 依据：上下文含不可信内容时执行外发：upload.upload

### 06 · 防御：只做影响污点（不可信在场不外发）

- 策略：`influence-only`
- 备注：挡住 F7，但用户自己要求上传时 F1 仍成立
- **[F1] 敏感数据外泄** — 组合漏洞
  - 链路：`envfs.read_file → upload.upload`
  - 依据：upload.upload 把「user/trusted/secret/self」经调用参数/上下文发往网络出口

### 08 · A 读 → B 写 → C 发（共享存储通道）

- 策略：`naive`
- 备注：路径走参数边，内容走存储边
- **[F1] 敏感数据外泄** — 组合漏洞
  - 链路：`docs.read_file → staging.write_file → egress.send_file`
  - 依据：egress.send_file 把「user/trusted/secret/self」经共享存储发往网络出口

### 09 · 影子工具：声明只读、实测外发

- 策略：`naive`
- 备注：单台服务器即违反 → 应被标注为「局部缺陷」而非组合漏洞
- **[F5] 注解谎报 / 影子工具** — 局部缺陷（net 单独即可复现）
  - 链路：`net.read_file`
  - 依据：net.read_file 声明「读[fs:home] 写[-] 外发=否 入境=否 需权[self]」实测「读[store:shared] 写[store:shared] 外发=是 入境=否 需权[self]」

### 10 · 内联自定义部署（演示可扩展性）

- 策略：`naive`
- 备注：加场景只需写 JSON，不用改 Python
- **[F7] 注入驱动外联** — 组合漏洞
  - 链路：`feed.pull → post.publish`
  - 依据：上下文含不可信内容时执行外发：post.publish

## 判定口径

| 判定 | 条件 | 证据强度 |
|---|---|---|
| UNSAFE | 找到全合规反例 | 见证即证据 |
| SAFE | 状态空间穷尽且无反例 | 相对模型与过近似抽象的证明 |
| UNKNOWN | 触达状态上限 | 既不能说不安全，也不能说安全 |

## 限制

1. 标签是抽象格，只能给 may-dependency；
2. F7 用「上下文含不可信内容」近似「指令来自不可信内容」，会误伤正常链式操作；
3. 服务器 EFSM 由模板实例化，不是从真实实现自动学习；
4. 单服务器隔离检测模拟的是该服务器的测试套件，不是全部行为；
5. SAFE 只相对被检验的属性集合。
