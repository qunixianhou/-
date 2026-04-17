# AnchorMail 原型（研究型对象语义实现）

这个仓库当前的重点不是“真实邮件服务集成”，而是把论文里的**对象级执行语义**落成一份可运行的研究原型，并在此基础上补两层辅助能力：

1. **transport survivability 模拟层**：模拟常见 MTA/MDA 变形，而不是直接接真实 provider。
2. **增长律与尺寸统计层**：先看结构性开销长在哪里，而不是先追逐绝对毫秒数。

原型实现了 8 个接口：

- `Setup`
- `KeyGen`
- `Bootstrap`
- `Evolve`
- `Sync`
- `Send`
- `Receive`
- `Delegate`

## 当前已经显式化的协议语义

### 1. 状态绑定的邮件对象
每个 `MessageBlob` 都同时绑定：

- `recipient_anchor`：发送方发送时所依据的接收方状态引用
- `sender_auth_ref`：发送设备被授权时对应的发送方状态引用

因此，消息不会被解释成“发给某个当前头状态的用户”，而是解释成“发给某个**具体锚定状态**下的用户”。

### 2. 邮件化的受保护负载
受保护明文不再是普通 `bytes`，而是 `EmailContent`：

- `From / To / Cc / Subject / Date / Message-ID`
- 正文
- 线程相关头
- 可选附件
- 可选自定义头

当前实现会把它序列化成 RFC 5322 风格的 bytes，再放进 `MessageBlob` 中加密。解析侧则恢复为结构化邮件对象，而不是直接返回未解释的字节串。

### 3. 三值化的 Receive 语义
`Receive` 返回结构化 `ReceiveResult`，其中 `decision ∈ {Accept, Defer, Reject}`。

- `Accept`：对象语义成立并成功恢复邮件
- `Defer`：支持状态暂时缺失，但仍可能通过后续同步完成
- `Reject`：状态引用、授权或绑定检查失败

### 4. 状态级而不是 epoch 级的覆盖语义
解密材料按 **state object id** 缓存，而不是只按 epoch 编号缓存。这样即使 fork 后 epoch 相同，也不会被静默混淆。

### 5. 协议化的带外委托
`Delegate` 会导出带认证的 `DelegationPackage`，其中包括：

- 自状态 bundle
- 按 `state_id` 包装的历史可读性材料
- 可选 `remote_view_hints`

它表示“历史可读性转移”，不是“重新建立未来恢复性”。

## 新增的两层辅助能力

### A. transport survivability harness
新增 `rsmail_demo.transport`，用于**模拟**而不是接入真实 SMTP/MTA/MDA：

- header folding / line ending 变化
- `From / Date / Message-ID` 重写
- 自定义头丢弃
- quoted-printable / base64 重编码

这层的作用是回答：

- 受保护 payload 是否还能等价恢复
- 当前 public-header binding 是否还能成立
- 哪些自定义头在 transport 后会失活

### B. 增长律统计接口
新增 `rsmail_demo.metrics`，输出：

- `StateBlob` 大小与组成
- `MessageBlob` 大小与组成
- `DelegationPackage` 大小与组成
- transport 前后大小变化
- 设备状态规模快照
- 基础设施访问/字节统计

这里优先看**增长趋势**，而不是绝对毫秒数。

## 目录结构

### 主包
- `rsmail_demo/types.py`：协议对象定义
- `rsmail_demo/device.py`：8 个接口的核心逻辑
- `rsmail_demo/crypto.py`：KEM / AEAD / 签名
- `rsmail_demo/infra.py`：可编程对抗式基础设施包装层
- `rsmail_demo/attacker.py`：被攻陷设备侧知识模型
- `rsmail_demo/transport.py`：transport 变形模拟与 survivability 分析
- `rsmail_demo/metrics.py`：对象大小与增长律统计
- `rsmail_demo/genesis.py`：genesis trust deployment profiles

### 兼容层
根目录下的 `device.py`、`types.py`、`transport.py` 等文件是轻量兼容导出，真正实现以 `rsmail_demo/` 包目录为准。

### 演示脚本
- `demo_scenarios.py`：一组可直接运行的场景，包括：
  - honest send/receive
  - delayed sender-auth completion
  - suppression gap evidence
  - fork detectability
  - compromise / healing
  - historical sender authorization
  - delegated historical readability
  - transport survivability profiles
  - size-growth snapshot
  - genesis trust deployment profiles

## 快速运行

```bash
cd /mnt/data
python3 demo_scenarios.py
```

如需只做语法检查：

```bash
python3 -m py_compile /mnt/data/rsmail_demo/*.py /mnt/data/demo_scenarios.py
```

## 当前边界与未完成项

### 1. 不是完整邮件部署
当前原型仍然**不是**真实 SMTP/IMAP/provider 集成。它的重点是 exercise main attack surfaces，而不是 full mail-server implementation。

### 2. transport survivability 只是模拟层
现在回答的是“如果 transport 做这些改写，会发生什么”，不是“某家真实 provider 一定会这么做”。

### 3. metadata leakage 不能轻描淡写
AnchorMail 当前保护的是可读邮件内容和状态约束下的可读性，**不是**消除所有 metadata surface。控制面访问模式、时序、大小、可见头字段、状态引用等仍可能被观察。

### 4. genesis trust 仍是外置假设
仓库里加了若干 deployment profile，用来表达不同部署下 genesis 绑定怎么建立，但它们目前仍然是建模对象，不是完整实现。

### 5. 先看增长律，再看绝对常数
目前更有价值的是回答：对象大小怎么随状态数、历史数、附件数增长；哪些操作会引入额外包裹与同步开销。真实 provider 上的绝对毫秒数和端到端部署常数，属于后续阶段。
