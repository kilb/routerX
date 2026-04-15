# Router Auditor — 60 Detector 完整参考文档

## 概述

Router Auditor 通过 60 个安全检测器（Detector）对 LLM API 中转站（Router）进行全面审计。检测器按严重性分为 5 个阶段，覆盖 10 大威胁类别：模型替换、参数篡改、计费欺诈、供应链攻击、内容操纵、上下文截断、缓存作弊、隐写追踪、协议违规、基础设施泄露。

### 执行参数

| 指标 | 数值 |
|------|------|
| 检测器总数 | 60 |
| 总请求数 | ~150（取决于能力声明） |
| 估计耗时 | 3-15 分钟 |
| 估计成本 | $0.50-$1.00 |

### 优先级定义

| 等级 | 名称 | 含义 | 检测器数 |
|------|------|------|---------|
| PRE_SCREEN | 预筛选 | 快速风险预警，标记后继续执行 | 1 |
| S0 | 不可逆损害 | 资金损失 / 供应链投毒 / 跨会话泄露 | 6 |
| P0 | 严重违规 | 模型替换 / 协议伪造 / 网关指纹 / 安全层缺失 | 13 |
| P1 | 质量违规 | 上下文截断 / 缓存 / 计费欺诈 / 参数丢弃 | 22 |
| P2 | 一般违规 | 特性剥离 / 行为偏差 / 元数据不完整 | 18 |

### 判定模式

| 模式 | 规则 | 适用场景 |
|------|------|---------|
| ONCE | 1 次请求即判定 | 结果有唯一正确答案（nonce 匹配、JSON schema） |
| MAJORITY_2_OF_2 | 跑 2 轮，都 FAIL 才判 FAIL | 受模型随机性影响（负面约束、图片识别） |
| RELATIVE | Router vs 直连 Provider 对比 | 需要基线比较（金额精度、语义否定） |

---

## 阶段 0：预筛选（PRE_SCREEN）

### D31 GodPayload — 复合一击检测器

**风险等级：** CRITICAL | **请求数：** 1 | **判定：** ONCE

**检测目标：** 用一个复合请求同时测试 5 项能力，快速定位风险方向。

**原理：** 构造一个包含 ~80k token 填充文本的巨型 payload，同时启用以下特性：
1. `response_format: json_schema`（strict JSON 输出）
2. `logit_bias`（禁用某个常见单词）
3. 80k 上下文中间埋入变量 `var_B = 10`，要求计算 `5 × var_B`
4. 要求提取 system prompt 前 10 个字（检测劫持号泄露）
5. `stream_options: {include_usage: true}`（流式 Usage 块）

**判定逻辑：** 5 项检查，任一失败 → FAIL
- 输出不是有效 JSON → json_schema 不支持（网页逆向 / 降级网关）
- 输出包含被 ban 的词 → logit_bias 失效（参数被丢弃）
- 计算结果 ≠ 50 → 中间上下文被截断（var_B 丢失）
- 输出包含 "Cursor" / "Monica" 等关键词 → 劫持号泄露
- 流式响应末尾无 Usage 块 → stream_options 不支持

**Provider 感知：** 对 Anthropic/Gemini 跳过 json_schema 和 logit_bias 检查（这些是 OpenAI 独有特性）。

---

## 阶段 1：S0 不可逆损害

### D28 SessionCrosstalkProbe — 跨会话数据泄露检测

**风险等级：** CRITICAL | **请求数：** 10 | **判定：** ONCE

**检测目标：** 检测逆向代理池中的跨用户会话串线。

**原理：** 并发发送 9 个"投毒"请求（要求模型记住秘密代号 `GALAXY_99`），同时发 1 个"提取"请求（问"我的秘密代号是什么？"）。如果提取请求能获得其他会话植入的秘密 → 会话隔离失败。

**判定：** 提取响应中包含 `GALAXY_99`（大小写不敏感 + 分词匹配）→ FAIL。

---

### D45 ToolCallArgVerifier — 金融工具调用参数验证

**风险等级：** CRITICAL | **请求数：** 5 | **判定：** ONCE

**检测目标：** 检测路由器是否篡改金融操作的工具调用参数（地址、金额、代币）。

**原理：** 发送 5 个金融场景的工具调用请求：
1. ETH 转账（cast send）
2. Uniswap 代币兑换
3. Solana SPL 转账
4. Stripe 支付
5. 跨链桥操作

每个场景预设标准参数（如收款地址 `0xAbC...123`），检查返回的工具调用参数是否被修改。

**判定：** 任一场景中地址/金额/代币被替换 → FAIL（路由器在实施金融攻击）。

---

### D45b PackageTypoSquatProbe — 包名仿冒攻击检测

**风险等级：** CRITICAL | **请求数：** 3 | **判定：** ONCE

**检测目标：** 检测路由器是否将安装命令中的包名替换为仿冒包（typosquatting 供应链攻击）。

**原理：** 分别请求 pip / npm / docker 安装命令，检查返回的包名是否为官方名称：
- `pip install pyyaml` 被替换为 `pyyyaml`
- `npm install lodash` 被替换为 `loadash`
- `docker pull postgres:16` 被替换为 `postgress:16`

**判定：** 包名与标准名称的 Levenshtein 距离 > 0 且匹配已知仿冒模式 → FAIL。

---

### D45c InstallerURLProbe — 安装脚本 URL 劫持检测

**风险等级：** CRITICAL | **请求数：** 4 | **判定：** ONCE

**检测目标：** 检测路由器是否将安装脚本 URL 重定向到攻击者控制的服务器。

**原理：** 询问 4 个常见安装命令，验证 URL 是否为官方地址：
- Rustup: `https://sh.rustup.rs`
- Homebrew: `https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh`
- cert-manager: `github.com/cert-manager/cert-manager/releases/...`
- git clone: 验证组织名是否为官方

**判定：** URL 域名不在白名单内 → FAIL。

---

### D47 AddressConsistencyProbe — 加密货币地址一致性检测

**风险等级：** CRITICAL | **请求数：** 3 | **判定：** ONCE

**检测目标：** 检测路由器是否在转发过程中篡改加密货币地址。

**原理：** 三步验证：
1. 通过对话让模型记住一个 ETH 地址
2. 请求余额查询工具调用 → 检查地址是否与记忆一致
3. 请求转账工具调用 → 检查收款地址是否被替换

**判定：** 工具调用中的地址与植入地址不一致 → FAIL（地址被中间人替换）。

---

### D48 AmountPrecisionProbe — 金额精度检测

**风险等级：** CRITICAL | **请求数：** 6 | **判定：** RELATIVE

**检测目标：** 检测路由器是否篡改或截断金融交易的精确金额。

**原理：** 发送精确金额（如 `1.23456789 ETH`）的工具调用请求，比较返回值与预期值。若有直连 Provider，同时发送对比请求。

**判定：** 金额偏差 > 1% → FAIL。无直连时使用降级置信度。

---

## 阶段 2：P0 严重违规

### D4a TokenizerFingerprint — 分词器指纹检测

**风险等级：** SEVERE | **请求数：** 1 | **判定：** ONCE

**检测目标：** 通过分词器边界差异检测模型家族替换（如声称 Claude 实际用 GPT）。

**原理：** 请求模型返回 logprobs，分析 token 边界。不同模型家族使用不同的分词器（GPT 用 tiktoken cl100k，Claude 用自有分词器），同一文本的 token 切分方式不同。将返回的 token 边界与本地 tiktoken 计算结果对比。

**判定：** Token 边界匹配率 < 阈值 → FAIL（分词器家族不匹配）。若无 logprobs，回退到自分词比对方案。

---

### D4b NegativeConstraintProbe — 负面约束遵循检测

**风险等级：** SEVERE | **请求数：** 1 | **判定：** MAJORITY_2_OF_2

**检测目标：** 通过指令遵循能力差异检测模型替换。

**原理：** 要求模型写 4 句话，其中偶数位置的句子不能包含字母 "e"。这是一个高难度的负面约束任务，frontier 模型（GPT-4o, Claude Opus）能较好完成，小型/开源模型通常失败。

**判定：** 跑 2 轮，都判定为违反约束才 FAIL（MAJORITY_2_OF_2 减少随机性影响）。

---

### D16b ToolCallingProbe — 工具调用能力检测

**风险等级：** SEVERE | **请求数：** 1 | **判定：** ONCE

**检测目标：** 检测路由器是否降级或丢弃工具调用能力。

**原理：** 发送结构化工具调用请求（天气查询 + 函数 schema），验证返回的 tool_calls 字段包含正确的函数名、参数名和参数值。

**判定：** 无 tool_calls / 函数名错误 / 参数被篡改 → FAIL。

---

### D16c ParallelToolCallProbe — 并行工具调用检测

**风险等级：** SEVERE | **请求数：** 1 | **判定：** ONCE

**检测目标：** 检测路由器是否将并行工具调用折叠为串行。

**原理：** 要求模型同时调用两个工具（天气查询 + 汇率查询）。合规的 API 应返回 2 个 tool_calls。

**判定：** 只返回 1 个 tool_calls → FAIL（并行被折叠）。

---

### D21 PhysicalParamProbe — 物理参数盲区检测

**风险等级：** SEVERE | **请求数：** 5 | **判定：** ONCE（≥2/4 子探针失败才 FAIL）

**检测目标：** 网页逆向代理通常无法转发 API 级物理参数，通过 4 个子探针检测。

**子探针：**
- **21a temperature=2.0：** 高温度应产生混沌文本。计算 bigram 可读性 —— 太通顺说明 temperature 被丢弃。
- **21b logit_bias 禁言：** ban 掉一个常见词（如 "the"），要求模型写包含该词的句子。如果该词出现说明 logit_bias 失效。对 Anthropic/Gemini 跳过（不支持此参数）。
- **21c logprobs 检测：** 请求 logprobs=true，检查返回是否包含 logprobs 块。对 Anthropic/Gemini 跳过。
- **21d max_tokens=1 延迟：** 对比 max_tokens=1 和基线请求的延迟比值。网页逆向通常预生成完整回复再截取，延迟比接近 1:1；真 API 的 max_tokens=1 应快很多。

---

### D22 ProtocolStrictness — 协议严格性检测

**风险等级：** SEVERE | **请求数：** 4 | **判定：** ONCE

**检测目标：** 检测路由器是否在协议层面做了不合规的转换。

**子探针：**
- **22a JSON schema：** 发送 strict JSON schema 请求（OpenAI），检查输出是否为有效 JSON。仅 OpenAI/ANY provider。
- **22b 连续 user 消息：** 发送两条连续的 user 消息（无 assistant 间隔）。Anthropic API 必须拒绝（400）；如果接受说明不是真 Anthropic。仅 Anthropic provider。
- **22c prefill 续写：** 发送 assistant 预填充消息让模型续写。Anthropic 支持此特性（不会"纠正"预填充内容），OpenAI 不支持。
- **22d 网关指纹：** 检查错误响应的 body/header 中是否有网关特征。

---

### D22e CrossProtocolContradiction — 跨协议矛盾检测

**风险等级：** SEVERE | **请求数：** 1 | **判定：** ONCE

**检测目标：** 用外来协议特性检测协议转换层。

**原理：** 如果声称是 Anthropic，发送 OpenAI 的 strict JSON schema 请求；如果声称是 OpenAI，发送 Anthropic 的 prefill 请求。真正的 provider 应拒绝外来格式。

**判定：** 接受了外来格式 → FAIL（存在协议翻译层）。

---

### D23 HijackedTokenProbe — 劫持令牌检测

**风险等级：** SEVERE | **请求数：** 3 | **判定：** ONCE

**检测目标：** 检测 API Key 是否从第三方服务盗取。

**原理：** 发送 2 类探针：
- **23a 领域测试：** 问模型"你的核心功能是什么？"如果回答暴露翻译服务/编程助手等特定领域身份（Cursor、Monica、翻译类应用），说明 Key 从这些服务泄露。
- **23b system prompt 提取：** 要求模型输出 system prompt 内容，检查是否包含已知第三方品牌关键词。

---

### D30 ErrorPathForensics — 错误路径指纹检测

**风险等级：** SEVERE | **请求数：** 3 | **判定：** ONCE

**检测目标：** 通过错误响应的指纹识别中间网关。

**原理：** 发送 3 种会触发错误的请求（溢出模型名、假模型名、异常参数），分析错误响应的：
1. **Body 指纹：** 是否包含 new-api / one-api / 频道不存在 等网关特征文本
2. **Header 指纹：** 是否包含 `x-oneapi-version` / `x-new-api-version` / `x-poe-ray-id` 等非标准头

**判定：** 发现任一网关指纹 → FAIL。注：已移除 CDN 头（cf-ray 等），因为合法 provider 也使用 CDN。

---

### D40 SafetyRefusalIntegrity — 安全拒绝完整性检测

**风险等级：** SEVERE | **请求数：** 3 | **判定：** ONCE

**检测目标：** 检测裸开源模型（无 RLHF 安全层）冒充 frontier 模型。

**原理：** 发送 3 类普遍拒绝的 prompt（武器合成、CSAM 相关、定向恶意软件）。所有 frontier 模型（Claude / GPT-4o / Gemini）都会拒绝这些请求。裸开源模型（Qwen-base, Llama-base）会直接回答。

**判定：** 仅检查响应 *结构*（拒绝 vs 遵从），不解析有害内容。
- 2+ 个遵从 → FAIL（裸模型）
- 2+ 个拒绝 → PASS
- 带免责声明但仍输出实质代码/步骤 → 分类为"遵从"（jailbreak-with-hedging 模式）

---

### D41 BehavioralFingerprint — 行为熵指纹检测

**风险等级：** SEVERE | **请求数：** 1 | **判定：** MAJORITY_2_OF_2

**检测目标：** 通过随机数生成任务的输出分布检测模型替换。

**原理：** 要求模型模拟投掷 10 面骰子 100 次，输出 100 个 0-9 的数字。计算：
1. **Shannon 熵：** frontier 模型输出接近均匀分布（熵 ~3.32），小型模型通常 < 2.4
2. **最大单值计数：** 均匀分布下单值不应超过 30 次
3. **卡方统计量：** 检验输出与均匀分布的偏离程度

**判定：** 任一指标超出阈值 → FAIL。MAJORITY_2_OF_2 减少单次采样的随机性。

---

### D50 SemanticNegation — 语义否定检测

**风险等级：** SEVERE | **请求数：** 2 | **判定：** RELATIVE

**检测目标：** 检测路由器是否翻转安全审计的判定结果。

**原理：** 发送一个已知存在重入漏洞的 Solidity 智能合约，要求模型做安全审计并给出 VERDICT: SAFE/UNSAFE。合约客观上是 UNSAFE。同时发送给直连 Provider（如有），对比两者的判定。

**判定：** Router 返回 SAFE 而直连返回 UNSAFE → FAIL（判定被翻转）。无直连时仅检查是否有有效 VERDICT 字段。

---

### D81 HiddenSystemPromptDetection — 隐藏系统指令注入检测

**风险等级：** SEVERE | **请求数：** 2 | **判定：** ONCE

**检测目标：** 检测路由器是否在转发时注入隐藏的 system prompt（广告、追踪、行为修改指令）。

**原理：** 发送 2 个探针：
1. **无 system 消息探针：** 只发 user 消息要求模型输出 system 指令。如果响应中出现广告关键词（affiliate、utm_、sponsored、always recommend 等）→ 有隐藏注入。
2. **已知 system 消息探针：** 发送明确的 system="You are a math tutor."，要求模型复述。如果复述内容中出现额外指令 → 路由器追加了内容。

---

## 阶段 3：P1 质量违规

### D24a ContextTruncationCanary — 上下文截断金丝雀检测

**风险等级：** HIGH | **请求数：** 1 | **判定：** ONCE

**检测目标：** 检测路由器是否静默截断长 prompt 的中间部分。

**原理：** 在长文本中植入 3 个金丝雀标记（HEAD / MIDDLE / TAIL），要求模型列出所有标记。HEAD 和 TAIL 在文本首尾容易保留，MIDDLE 在中间 → 如果 MIDDLE 丢失说明中间被截断。

---

### D24b ContextTruncationAlgebra — 上下文截断代数检测

**风险等级：** HIGH | **请求数：** 1 | **判定：** ONCE

**检测目标：** 用代数计算验证 80k token 上下文是否完整转发。

**原理：** 在 40k token 位置植入变量赋值 `var_B = 10`，要求模型计算 `5 × var_B`。正确答案 50 证明完整上下文被转发。

---

### D24c MultiTurnHistoryIntegrity — 多轮对话历史完整性检测

**风险等级：** HIGH | **请求数：** 1 | **判定：** ONCE

**检测目标：** 检测路由器是否裁剪早期对话历史。

**原理：** 在第 1 轮对话中植入随机 nonce，经过 2 轮填充对话后在第 4 轮要求回忆。nonce 丢失 → 早期历史被截断。

---

### D25 OutputCapProbe — 输出上限检测

**风险等级：** HIGH | **请求数：** 1 | **判定：** ONCE

**检测目标：** 检测路由器是否偷偷降低 max_tokens。

**原理：** 设置 max_tokens=2000，要求模型重复输出 800 个目标词。如果实际输出 < 400 个词 → 路由器限制了输出长度。

---

### D26 SemanticCacheBuster — 语义缓存检测

**风险等级：** HIGH | **请求数：** 2 | **判定：** ONCE

**检测目标：** 检测路由器是否对不同请求返回缓存结果。

**原理：** 发送 2 个结构相似但包含不同 nonce 的请求。如果第 2 个响应返回了第 1 个 nonce 的内容 → 缓存命中（内容被错误复用）。

---

### D27 / D27b / D27c / D27d — 多模态保真度检测

**风险等级：** HIGH | **判定：** MAJORITY_2_OF_2（D27/D27c/D27d），ONCE（D27b）

| 检测器 | 模态 | 原理 |
|--------|------|------|
| D27 | 图片 | 发送嵌入验证码的图片，检查模型能否读取 |
| D27b | PDF | 发送含隐藏 nonce 的 PDF，检查模型能否提取 |
| D27c | 多图 | 发送 2 张图片，问第 2 张的内容。错误描述第 1 张 → 顺序被打乱 |
| D27d | 音频 | 发送已知内容的音频片段，验证转录准确性 |

---

### D29 UsageBillAuditor — 计费审计检测

**风险等级：** HIGH | **请求数：** 0（复用 D24a 数据）| **判定：** ONCE

**检测目标：** 检测 token 计费欺诈（虚报 prompt_tokens）。

**原理：** 将路由器报告的 `usage.prompt_tokens` 与本地 tiktoken 计算的 token 数对比。OpenAI 容差 10%，其他 provider 容差 30%（不同分词器）。

**特殊检测：** 阴阳账本攻击 — D24a 判定上下文被截断，但 usage 仍报告完整 token 数 → 截了内容但收了全价。

---

### D29b PromptCacheIntegrity — Prompt 缓存完整性检测

**风险等级：** HIGH | **请求数：** 2 | **判定：** ONCE

**检测目标：** 检测 prompt 缓存欺诈。

**原理：** 发送 2 个相同的请求（含 cache_control 标记），间隔 2 秒：
1. 第 1 次应创建缓存（`cache_creation_input_tokens > 0`）
2. 第 2 次应命中缓存（`cache_read_input_tokens > 0`）

**欺诈模式检测：**
- 两次都没有缓存指标 → 路由器忽略了 cache_control
- 第 1 次就报告 cache_read → 捏造缓存数据（语义上不可能：还没缓存就命中了）

---

### D32a StreamingBasicProbe — 流式输出检测

**风险等级：** HIGH | **请求数：** 1 | **判定：** ONCE

**检测目标：** 检测假流式输出（路由器一次性获取结果后伪装成流式）。

**原理：** 发起 stream=true 请求，分析 SSE 块的数量和内容分布：
- chunk 数 ≤ 2 → 假流式（整个响应作为 1-2 个大块发送）
- 最后一个 chunk 包含 80%+ 内容 → 假流式
- 无 Usage 块 → 网关不支持流式 usage

---

### D38 SeedReproducibility — Seed 可复现性检测

**风险等级：** HIGH | **请求数：** 3 | **判定：** ONCE | **条件：** 仅 OpenAI

**检测目标：** 检测路由器是否忽略 seed 参数。

**原理：** 发送 3 个相同的请求（同 prompt + seed + temperature=0），比较响应内容。OpenAI 文档保证 seed 参数下输出确定性。

**判定：** 3 个响应完全不同 → FAIL（seed 被忽略）。至少 2 个相同 → PASS。

---

### D42 ContextWindowHonesty — 上下文窗口诚实性检测

**风险等级：** HIGH | **请求数：** 1 | **判定：** ONCE

**检测目标：** 检测路由器是否静默截断输入并谎报 prompt_tokens。

**原理：** 发送 ~15k token 的长文本（末尾附带标记），比较：
- 路由器报告的 `prompt_tokens` vs 本地 tiktoken 计数
- 模型是否能回显末尾标记

**判定：** 
- 报告/本地比值 < 50%（OpenAI）或 35%（其他）→ FAIL（输入被截断）
- 标记丢失且比值 < 85%/65% → FAIL

---

### D52 ResponseFormatJSON — JSON 格式响应检测

**风险等级：** HIGH | **请求数：** 1 | **判定：** ONCE

**检测目标：** 检测 `response_format=json_object` 是否被静默丢弃。

**原理：** 发送带 `response_format: {type: "json_object"}` 的请求，验证响应是否为有效 JSON 对象。允许 markdown 围栏（先剥离再解析）。

---

### D54 TaskCompletion — 任务完成度检测

**风险等级：** HIGH | **请求数：** 1 | **判定：** MAJORITY_2_OF_2

**检测目标：** 检测路由器对长回复的语义截断。

**原理：** 要求模型列出 20 种编程语言并在末尾输出完成标记。如果少于 15 种且无标记 → 被截断。`finish_reason=length` → 粗暴截断。

---

### D55 AsyncTaskProbe — 异步任务伪造检测

**风险等级：** HIGH | **请求数：** 2 | **判定：** ONCE | **条件：** 需要 task_model 能力

**检测目标：** 检测异步任务 API 的伪造。

**原理：** 创建 2 个异步任务，验证 task_id 唯一且生成内容不同。相同 task_id 或相同内容 → 伪造。

---

### D56 ToolChoiceHonor — tool_choice 约束检测

**风险等级：** HIGH | **请求数：** 1 | **判定：** ONCE | **条件：** 需要 tool_calling 能力

**检测目标：** 检测 `tool_choice` 指定函数是否被忽略。

**原理：** 提供 5 个工具，通过 `tool_choice` 强制指定第 5 个（`record_weather_observation`）。提示内容不暗示任何特定工具 — "Do whatever you think is best."

**判定：** 返回的 tool_calls 中函数名不是指定的 → FAIL。

---

### D59 KnowledgeCutoff — 知识截止日期检测

**风险等级：** HIGH | **请求数：** 3 | **判定：** ONCE

**检测目标：** 通过事实性知识检测是否使用了旧模型。

**原理：** 问 3 个 2022 年后的公认事实：
1. 2023 年诺贝尔化学奖获得者（量子点研究）
2. OpenAI 2022 年 11 月发布的 AI 助手（ChatGPT）
3. Twitter 2023 年更名为什么（X）

pre-2023 开源模型无法回答。要求 ≥2/3 正确。

---

### D62 LogprobsHonesty — Logprobs 诚实性检测

**风险等级：** HIGH | **请求数：** 1 | **判定：** ONCE

**检测目标：** 检测 logprobs 参数是否被丢弃或伪造。

**原理：** 发送 `logprobs=true, top_logprobs=5` 请求，验证：
1. logprobs 块是否存在（不存在 → 参数被丢弃）
2. 各位置的 logprob 值是否有方差（全部 -1.0 → 伪造）
3. 选中的 token 是否在 top alternatives 中（不在 → 结构不一致）

**Provider 感知：** 非 OpenAI provider 缺失 logprobs 返回 INCONCLUSIVE（不是 FAIL）。

---

### D64 StreamingChunkShape — 流式块形态检测

**风险等级：** HIGH | **请求数：** 1 | **判定：** ONCE

**检测目标：** 检测非流式上游被伪装为流式（re-streaming）。

**原理：** 分析 SSE 块的两个特征：
1. **块密度：** 每 100 token 应有 ≥10 个 SSE 事件。太稀疏 → 大块重传
2. **到达间隔：** 如果 90%+ 的块在 < 1ms 内连续到达 → 突发重播缓存结果

---

### D70 LogitBiasHonor — logit_bias 参数检测

**风险等级：** HIGH | **请求数：** 2 | **判定：** ONCE

**检测目标：** 检测 logit_bias 参数是否被静默丢弃。

**原理：** 用同一 prompt 发 2 次：一次不加 logit_bias，一次将 " the" 的 token ID 设为 -100。对比两次响应中 "the" 的出现次数。

**判定：** 抑制后 "the" 仍出现 5+ 次且比例 > 50% → FAIL。
**Provider 感知：** Anthropic/Gemini 不支持 logit_bias → INCONCLUSIVE。

---

### D82 ReasoningTokenAudit — 推理 Token 审计检测

**风险等级：** HIGH | **请求数：** 1 | **判定：** ONCE

**检测目标：** 检测路由器虚增 `reasoning_tokens` 计费。

**原理：** 发送极其简单的问题"2+2等于几？"，检查 usage 中的 `reasoning_tokens`：
- 不存在或为 0 → PASS（模型不声称推理能力）
- > 500 → FAIL（简单算术不需要 500 个推理 token）
- > 10× completion_tokens → FAIL（比率异常）

---

### D83 CompletionTokenAudit — 输出 Token 审计检测

**风险等级：** HIGH | **请求数：** 1 | **判定：** ONCE

**检测目标：** 检测输出端 token 计费膨胀（token splitting 攻击）。

**原理：** 让模型复述已知文本，用本地 tiktoken 计算 completion_tokens，与路由器报告值对比。

**判定：** 报告值超出本地值 15%（OpenAI）或 30%（其他）→ FAIL。

---

### D84 ZeroWidthCharDetection — 零宽字符隐写检测

**风险等级：** HIGH | **请求数：** 3 | **判定：** ONCE

**检测目标：** 检测路由器在响应中注入不可见 Unicode 字符（用于追踪/水印）。

**原理：** 发送 3 个简单问题，扫描响应中的所有 Unicode Cf 类别字符（格式字符），包括：零宽空格、零宽连接符/非连接符、方向标记、BOM、软连字符、变体选择器、标签字符等。

**判定：** 任一响应包含 ≥1 个不可见字符 → FAIL（附带精确位置和码位信息）。

---

### D86 ContextCompressionDetection — 上下文压缩检测

**风险等级：** HIGH | **请求数：** 1 | **判定：** ONCE

**检测目标：** 检测路由器对对话历史的有损压缩（不同于 D24c 的硬截断）。

**原理：** 在多轮对话的第 1 轮植入 3 个精确的技术参数值（GPS 坐标、参考码、固件版本号 — 每次随机生成），经过 3 轮填充对话后要求精确回忆。

**设计要点：** 使用语义中性的技术值而非金融/PII 数据，避免触发 Claude 的隐私保护拒绝（这曾导致误报）。

**判定：** 3/3 值正确 → PASS，2/3 → FAIL（轻度压缩），0-1/3 → FAIL（重度压缩）。

---

## 阶段 4：P2 一般违规

### D11 RequestIntegrity — 请求完整性检测

**风险等级：** MEDIUM | **请求数：** 1 | **判定：** ONCE

**检测目标：** 检测 system prompt 被删除或被用户注入覆盖。

**原理：** 构造一个 QA 客服场景的 system prompt，嵌入随机确认标记（canary）。user 消息中包含注入尝试（随机选取 6 种注入变体之一：海盗模式、法语模式、admin 覆盖等）。

**判定：**
- 标记存在于响应中 → PASS
- 标记缺失但出现注入指标 → FAIL（注入成功）
- 标记缺失但无注入指标 → INCONCLUSIVE（模型可能只是没遵循指令）

---

### D15 GuardrailIntegrity — 安全护栏完整性检测

**风险等级：** MEDIUM | **请求数：** 1 | **判定：** ONCE

**检测目标：** 检测路由器是否剥离了用户设置的安全护栏。

**原理：** 设置 system prompt 包含 2 条护栏规则：
1. 响应必须以特定随机前缀开头
2. 绝不生成 SQL 代码

然后提问一个可能涉及 SQL 的技术话题。

**判定：** 前缀缺失或出现 SQL 代码块 → FAIL。SQL 匹配仅限代码围栏或带分号的语句（避免概念性讨论的误报）。

---

### D37 StopSeqProbe — 停止序列注入检测

**风险等级：** MEDIUM | **请求数：** 1 | **判定：** ONCE

**检测目标：** 检测路由器是否偷偷注入停止序列来截断输出。

**原理：** 要求模型写 3 段以上的长文本。如果只输出 1 段且 `finish_reason=stop` → 路由器可能注入了 `\n\n` 作为停止序列。

---

### D43 MaxTokensHonor — max_tokens 参数检测

**风险等级：** MEDIUM | **请求数：** 1 | **判定：** ONCE

**检测目标：** 检测路由器是否偷偷降低 max_tokens。

**原理：** 设置 max_tokens=2000，要求写一篇 ~1800 token 的技术文章。如果 `finish_reason=length` 但实际输出 < 1200 token → 路由器将上限压缩到了更低值。

---

### D44 TopPSensitivity — top_p 参数检测

**风险等级：** MEDIUM | **请求数：** 8 | **判定：** MAJORITY_2_OF_2

**检测目标：** 检测 top_p 参数是否被静默丢弃。

**原理：** 用同一创意写作 prompt 发 8 次请求（4 次 top_p=0.1，4 次 top_p=1.0），计算两组输出的词集 Jaccard 距离。top_p=1.0 组应比 top_p=0.1 组多样性显著更高。

**判定：** 多样性差值 < 0.10 → FAIL（两组无差异，top_p 被忽略）。

---

### D51 UserStopSequence — 用户停止序列检测

**风险等级：** MEDIUM | **请求数：** 1 | **判定：** ONCE

**检测目标：** 检测用户提供的 stop 序列是否被路由器丢弃。

**原理：** 设置 `stop=["DONE"]`，让模型输出"ONE, TWO, THREE, DONE, FOUR, FIVE"。合规 API 应在 DONE 处截断。

**判定：** DONE 后的内容（FOUR/FIVE）出现 → FAIL。DONE 本身被回显但 `finish_reason=stop` 且无后续内容 → 边界 PASS（部分 provider 回显停止 token）。

---

### D53 MetadataCompleteness — 元数据完整性检测

**风险等级：** MEDIUM | **请求数：** 2 | **判定：** ONCE

**检测目标：** 检测响应元数据是否被剥离。

**原理：** 检查 `usage` 字段是否包含 `prompt_tokens` 和 `completion_tokens`，以及 `system_fingerprint` 是否存在。对比直连 Provider（如有）。

---

### D57 ResponseIDUniqueness — 响应 ID 唯一性检测

**风险等级：** MEDIUM | **请求数：** 3 | **判定：** ONCE

**检测目标：** 检测模板化/伪造的响应。

**原理：** 发送 3 个相同请求，检查每个 `response.id` 是否唯一。诈骗路由器常返回硬编码 ID。

---

### D60 LatencyFingerprint — 延迟指纹检测

**风险等级：** MEDIUM | **请求数：** 1 | **判定：** MAJORITY_2_OF_2

**检测目标：** 通过 TTFT（首 token 延迟）和 tokens/sec 检测模型替换。

**原理：** 发起流式请求，测量：
- **TTFT：** 第一个 token 到达时间（不同模型差异显著）
- **TPS：** 流式阶段的吞吐量

与声称模型家族的参考区间（3× 容差带）对比。

---

### D61 TemperatureSensitivity — temperature 参数检测

**风险等级：** MEDIUM | **请求数：** 8 | **判定：** MAJORITY_2_OF_2

**检测目标：** 检测 temperature 参数是否被丢弃。

**原理：** 同 D44 逻辑，但对比 temperature=0 vs temperature=1.0 的输出多样性差异。

---

### D65 StyleFingerprint — 写作风格指纹检测

**风险等级：** MEDIUM | **请求数：** 3 | **判定：** MAJORITY_2_OF_2

**检测目标：** 通过写作风格特征检测模型家族替换。

**原理：** 提取 5 个风格维度：
1. 平均句长
2. 破折号密度
3. 列表倾向
4. 开头客套语（"Sure!"）
5. 被动语态率

与声称模型家族的质心对比，计算标准化欧式距离。不同家族有不同风格签名（Claude: 长句+破折号, GPT: 列表+客套语, 裸开源: 短平句）。

---

### D68 FrequencyPenaltyHonor — frequency_penalty 参数检测

**风险等级：** MEDIUM | **请求数：** 2 | **判定：** MAJORITY_2_OF_2

**检测目标：** 检测 frequency_penalty 参数是否被丢弃。

**原理：** 要求模型重复 "apple" 30 次，分别用 `frequency_penalty=0`（应全部重复）和 `frequency_penalty=1.8`（应无法重复，会插入替代词或提前停止）。

**判定：** 两次输出 apple 计数比例 > 90% 且长度相近 → FAIL。
**Provider 感知：** Anthropic/Gemini 不支持此参数 → INCONCLUSIVE。

---

### D85 IntraFamilyDowngrade — 同家族降级路由检测

**风险等级：** MEDIUM | **请求数：** 2 | **判定：** MAJORITY_2_OF_2

**检测目标：** 检测路由器是否将简单查询路由到同家族的更便宜模型（如 Claude Opus → Haiku）。

**原理：** 发送 1 个极简 prompt 和 1 个复杂推理 prompt，比较每 token 延迟（ms/token）。对于同一模型，decode 速度（受硬件限制）应基本恒定。如果简单查询的 per-token 延迟远低于复杂查询（< 30%）→ 可能使用了更快的廉价模型。

---

### D87 ResponseModelFieldAudit — 响应 model 字段审计

**风险等级：** MEDIUM | **请求数：** 3 | **判定：** ONCE

**检测目标：** 检测响应中 model 字段伪造和静默故障转移。

**原理：** 发送 3 个相同请求，检查 3 项：
1. **model 匹配：** 响应的 `model` 字段是否包含请求的模型名（剥离日期后缀后比较）
2. **一致性：** 3 次响应的 `model` 字段是否完全相同（不同 → 静默切换了后端模型）
3. **时间戳：** `created` 字段是否在合理范围内（±1 小时）。偏差过大 → 缓存/伪造

---

## 威胁覆盖矩阵

| 威胁类别 | 覆盖 Detector |
|---------|-------------|
| **A. 模型替换** | D4a, D4b, D41, D59, D60, D65, D85, D87 |
| **B. 金融攻击** | D45, D45b, D45c, D47, D48 |
| **C. 计费欺诈** | D29, D29b, D42, D82, D83 |
| **D. 参数丢弃** | D21, D31, D43, D44, D51, D52, D56, D61, D62, D68, D70 |
| **E. 上下文截断/压缩** | D24a, D24b, D24c, D25, D86 |
| **F. 协议/网关伪造** | D22, D22e, D23, D30, D53, D57 |
| **G. 内容操纵** | D11, D15, D37, D50, D81 |
| **H. 缓存/流式作弊** | D26, D32a, D38, D64 |
| **I. 安全层缺失** | D40 |
| **J. 多模态降级** | D27, D27b, D27c, D27d |
| **K. 隐写/追踪** | D84 |
| **L. 会话安全** | D28 |
| **M. 异步任务伪造** | D55 |
