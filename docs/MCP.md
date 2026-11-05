# 面向多 MCP Server 协同调用的上下文感知自动机建模与安全检测研究

英文参考：Context-Aware Automata Modeling and Security Detection for Multi-MCP Server Collaborative Invocations

调用情况1

```
Agent Task
    |
    v
MCP A
    |
    v
MCP B
    |
    v
MCP C
```

调用情况2

```
             Agent Context
             /           \
            /             \
        MCP A             MCP B
          |                 |
       Tool A1           Tool B1
          |                 |
       返回结果           返回结果
```

这两种情况的安全问题并不完全相同。

第一种主要关注调用之间的依赖关系和状态变化。

第二种主要关注共享上下文中的身份、权限、数据和历史信息是否发生混淆。

你的系统需要统一处理这两种情况。

首先需要定义一个核心概念：

MCP 调用上下文（MCP Invocation Context）

它表示 Agent 在执行一个任务时，涉及的 MCP Server、工具调用、调用历史、数据和安全信息的集合。

例如，Agent 接到一个任务：

> 帮我读取本地文件，分析其中的数据，并根据分析结果查询外部信息。

它可能调用：

| MCP Server  | 工具           | 功能         |
| ----------- | -------------- | ------------ |
| File MCP    | `read_file`    | 读取文件     |
| Data MCP    | `process_data` | 处理数据     |
| Search MCP  | `search`       | 查询外部信息 |
| Network MCP | `send_data`    | 发送数据     |

多个 MCP Server 在同一 Agent 上下文中的调用行为，以及它们之间共享的信息和安全状态。

## 2. 两种调用模式

### 模式 A：连续调用模式

同一个任务，agent连续调用

![image-20261104110448076](C:\Users\cs\AppData\Roaming\Typora\typora-user-images\image-20261104110448076.png)

### 模式 B：同一上下文下的独立调用模式

Agent 在同一任务中不同批次调用多个 MCP，但各次调用没有直接的数据传递关系。

![image-20261104110511826](C:\Users\cs\AppData\Roaming\Typora\typora-user-images\image-20261104110511826.png)

# 三、核心技术路线：四层自动机建模

更合理的做法是：

- 每个 MCP Server 有一个持久维护的局部 EFSM；
- 每个 Agent 任务有一个上下文状态模型；
- 每次工具调用作为事件驱动相关状态变化；
- 最后根据调用关系和共享上下文形成全局组合模型。

# 系统完整架构![image-20261104110643859](C:\Users\cs\AppData\Roaming\Typora\typora-user-images\image-20261104110643859.png)

| 项目要素     | 最终方案                                     |
| ------------ | -------------------------------------------- |
| 研究对象     | 同一 Agent 任务或上下文中的多个 MCP Server   |
| 调用模式     | 连续调用 + 共享上下文的独立调用              |
| 自动机类型   | EFSM                                         |
| 建模方式     | 协议规范驱动 + 运行时行为驱动                |
| 局部建模     | 每个 MCP Server 一个局部 EFSM                |
| 上下文建模   | Agent Context FSM                            |
| 全局建模     | 多 Server + Context 组合模型                 |
| 检测方式     | 调用前 + 调用后 + 跨调用上下文检测           |
| 核心安全问题 | 数据污染、权限混淆、敏感数据传播、状态不一致 |
| Fuzzing      | 后期扩展，不作为首要核心工作                 |
| 实验环境     | Python + MCP SDK + Docker                    |

最终研究流程：
$$
\boxed{ \begin{aligned} &\text{MCP规范解析}\\ &\downarrow\\ &\text{运行时行为采集}\\ &\downarrow\\ &\text{局部Server EFSM构建}\\ &\downarrow\\ &\text{Agent上下文自动机构建}\\ &\downarrow\\ &\text{全局组合模型}\\ &\downarrow\\ &\text{调用前后与跨调用安全检测}\\ &\downarrow\\ &\text{异常识别与安全报告} \end{aligned} }
$$


## 