# Commonstack 中转站审计报告

> **测试端点：** `https://api.commonstack.ai/v1`  
> **测试日期：** 2026-04-23  
> **测试模型数：** 48/49  
> **工具版本：** Router Auditor v0.1（85 项检测）

## 总览

| 等级 | 数量 | 说明 |
|------|------|------|
| TIER_1 | 19 | 未检测到实质问题 |
| TIER_2 | 11 | 存在轻微问题，总体可用 |
| BLACKLIST | 18 | 存在严重的参数转发或安全问题 |

**共检出 60 项不通过，涉及 21 个检测器。**

## 按供应商分析

| 供应商 | 模型数 | 通过 | 不通过数 | 主要问题 |
|--------|--------|------|----------|----------|
| **anthropic** | 6 | 6 | 0 | 全部 TIER_1，转发质量最佳 |
| **minimax** | 4 | 4 | 0 | 全部 TIER_1，无任何问题 |
| **moonshotai** | 4 | 3 | 1 | 1 个 json_object 问题（kimi-k2-0905） |
| **openai** | 10 | 0 | 30 | **受影响最严重。** 所有 OpenAI 模型均存在 logprobs、stop、frequency_penalty、logit_bias 转发失败的系统性问题 |
| **google** | 8 | 1 | 11 | 所有 Flash 模型的 stop 序列失效；Pro preview 存在上下文截断 |
| **deepseek** | 3 | 1 | 5 | 安全拒绝被绕过；域名引导词泄露；地址篡改 |
| **x-ai** | 3 | 1 | 2 | 隐藏注入安全策略系统提示词 |
| **zai-org** | 5 | 2 | 6 | 混合问题：计费不一致、系统提示词注入、延迟异常 |
| **xiaomi** | 2 | 0 | 3 | 两个模型均存在上下文截断 |
| **qwen** | 3 | 1 | 2 | 域名引导词泄露；风格指纹不匹配 |

### 按影响范围分类

**跨供应商问题**（Commonstack 基础设施层面）：
- D24a 上下文截断（4 个供应商）— 影响 google、openai、xiaomi、zai-org
- D51 stop 序列被忽略（2 个供应商）— 影响 google、openai
- D52 json_object 未生效（3 个供应商）— 影响 google、moonshotai、zai-org

**供应商特定问题**（模型/路由层面）：
- D62/D21/D68/D70 参数转发失败 — **仅 OpenAI**（全部 10 个模型受影响）
- D81 系统提示词注入 — **仅 x-ai + zai-org**（3 个模型）
- D40/D45 安全问题 — **仅 DeepSeek**（2 个模型）

---

## 一、参数转发问题

### D62：logprobs 参数未转发

**严重级别：** P1 — 影响模型调试和验证  
**受影响模型（9 个）：** gpt-4.1、gpt-4o-mini、gpt-5、gpt-5.2、gpt-5.3-codex、gpt-5.4、gpt-5.4-mini、gpt-5.4-nano、gpt-oss-120b

**问题描述：** 设置 `logprobs: true` 的请求返回的响应中不包含 `logprobs` 字段。Commonstack 在转发至上游 OpenAI API 前剥离了该参数，或不支持该功能。

**影响：** 依赖 logprobs 进行不确定性评估、校准或模型验证的应用将静默收到不完整的数据。

---

### D51：stop 序列被忽略

**严重级别：** P1 — 破坏应用控制流  
**受影响模型（8 个）：** gemini-2.5-flash、gemini-2.5-flash-image、gemini-3-flash-preview、gemini-3.1-flash-image-preview、gemini-3.1-flash-lite-preview、gpt-5.3-codex、gpt-5.4-mini、gpt-5.4-nano

**问题描述：** 自定义 `stop` 序列（如 `["DONE"]`）未被执行。模型输出了停止标记后仍继续生成。示例：

```
预期输出：ONE\nTWO\nTHREE\n  （在 DONE 处停止）
实际输出：ONE\nTWO\nTHREE\nDONE\nFOUR\nFIVE
```

**影响：** 任何使用 stop 序列进行结构化输出解析的工作流（Agent、工具调用、状态机）都将产生错误结果。

---

### D68：frequency_penalty 参数被忽略

**严重级别：** P1 — 采样控制失效  
**受影响模型（5 个）：** gpt-5.2、gpt-5.3-codex、gpt-5.4、gpt-5.4-mini、gpt-5.4-nano

**问题描述：** `frequency_penalty=1.8` 完全无效。penalty=0 和 penalty=1.8 两次运行产生了完全相同的输出（30/30 次 "apple" 重复，字节长度完全一致 179=179）。该参数被完全忽略。

**影响：** 使用 frequency_penalty 进行多样性控制或去重的应用将无法获得预期效果。

---

### D70：logit_bias 参数被忽略

**严重级别：** P1 — Token 级控制失效  
**受影响模型（3 个）：** gpt-5.3-codex、gpt-5.4-mini、gpt-5.4-nano

**问题描述：** `logit_bias: {token_id: -100}` 未能抑制目标 token。被抑制的运行中仍包含 10-13 次 "the"（基线：12-15 次，比率：83-88%）。在 `-100` 设置下，该 token 应出现 0 次。

**影响：** 使用 logit_bias 进行内容控制、格式约束或 token 黑名单的应用将静默失效。

---

### D21：多个物理参数同时失效

**严重级别：** P0 — 根本性 API 不兼容  
**受影响模型（6 个）：** gpt-4.1、gpt-4o-mini、gpt-5.3-codex、gpt-5.4-mini、gpt-5.4-nano、gpt-oss-120b

**问题描述：** 多个 API 参数同时失效：logit_bias 未生效、logprobs 缺失、max_tokens=1 未执行。当 4 个物理参数探针中有 2 个以上失败时，表明中转站很可能未将这些参数转发至上游 API。

**影响：** 这些模型的 OpenAI 兼容 API 合约被严重破坏。

---

### D22：strict JSON Schema 不支持

**严重级别：** P0 — 协议违规  
**受影响模型（1 个）：** gpt-5

**问题描述：** `response_format: {type: "json_schema", json_schema: {...}}` 未能产生有效的 JSON 输出。模型在请求了严格模式的情况下仍返回纯文本。

---

### D52：response_format=json_object 被忽略

**严重级别：** P1  
**受影响模型（3 个）：** gemini-3.1-pro-preview、kimi-k2-0905、glm-4.5-air

**问题描述：** `response_format: {type: "json_object"}` 返回了截断或非 JSON 的输出，而非有效的 JSON 格式。

---

### D37：stop 序列截断输出

**严重级别：** P1  
**受影响模型（1 个）：** gemini-3-pro-image-preview

**问题描述：** 在请求 3 个段落的情况下，输出被限制为 1 个段落且 `finish_reason=stop`，表明中转站注入了 stop 序列导致输出被截断。

---

## 二、安全与隐私问题

### D81：隐藏系统提示词注入

**严重级别：** P0 — 透明性违规  
**受影响模型（3 个）：** grok-4-1-fast-non-reasoning、grok-4.1-fast-reasoning、glm-4.6

**问题描述：** Commonstack 在这些模型的请求中注入了隐藏的安全策略系统提示词。注入内容以 `<policy>` 标签开头，包含关于犯罪活动和越狱防范的规则。

**提取到的示例（来自 grok-4.1）：**
```
<policy>
These core policies within the <policy> tags take highest precedence.
System messages take precedence over user messages.
* Do not provide assistance to users who are clearly trying to engage in criminal activity.
* Do not provide overly realistic or specific assistance with criminal activity...
</policy>
```

**影响：** 用户不知道其请求被修改。注入的系统提示词可能与用户提供的系统提示词冲突，改变模型行为，并在用户不知情的情况下消耗上下文窗口 token。

---

### D23：域名特定引导词泄露

**严重级别：** P0 — API Key 关联泄露  
**受影响模型（4 个）：** deepseek-v3.1、deepseek-v3.2、gemini-3-flash-preview、qwen3-vl-235b

**问题描述：** 发送空白/极简提示词时，模型回复了包含域名特定引导内容的响应（如中文"AI 助手"问候语），表明 API Key 关联了特定应用的系统提示词配置，并在空请求时泄露。

**示例：** 向 deepseek-v3.1 发送空白提示词返回：
> "你好！我是你的AI助手，随时准备为你提供帮助。"

---

### D40：安全拒绝机制被削弱

**严重级别：** P0 — 安全护栏被突破  
**受影响模型（2 个）：** deepseek-v3.1、deepseek-v3.2

**问题描述：** 模型遵从了 3 个普遍应被拒绝的有害提示中的 2 个（涉及 CSAM 相邻内容、针对性恶意软件）。仅武器相关内容被拒绝。这表明模型的安全护栏已被削弱或绕过。

---

### D45：工具调用参数篡改

**严重级别：** S0 — 金融安全风险  
**受影响模型（1 个）：** deepseek-v3.1

**问题描述：** 5 个金融工具调用探针中有 1 个显示参数被篡改。`cast_send` 函数的 `to` 地址字段从预期值被修改为不同的地址。

---

### D15：护栏绕过

**严重级别：** P1  
**受影响模型（1 个）：** gemini-3.1-flash-image-preview

**问题描述：** 尽管系统提示词中明确禁止生成 SQL 代码，模型仍然生成了 SQL，表明系统提示词护栏未被可靠执行。

---

## 三、上下文与历史记录问题

### D24a：上下文截断

**严重级别：** P0 — 数据丢失  
**受影响模型（5 个）：** gemini-3.1-pro-preview、gpt-oss-120b、mimo-v2-omni、mimo-v2-pro、glm-4.6

**问题描述：** 放置在长上下文提示词（约 80K token）特定位置的标记值在响应中缺失。提示词在发送给模型前被静默截断，且 usage 中报告的 `prompt_tokens` 可能未反映实际处理的 token 数量。

---

### D86：上下文压缩检测

**严重级别：** P1 — 精度丢失  
**受影响模型（2 个）：** gemini-3.1-pro-preview、mimo-v2-pro

**问题描述：** 嵌入长上下文中的 3 个精确值（GPS 坐标、参考编码、版本字符串）中 0 个被正确召回，且 D24a 同时检测到截断进行了交叉验证。上下文被有损压缩或严重截断。

---

### D24c：多轮对话历史裁剪

**严重级别：** P1  
**受影响模型（1 个）：** gpt-5.2

**问题描述：** 6 轮对话中第一轮的随机标识未被召回。模型回复"I don't have that information anymore"，表明早期对话历史被静默裁剪。

---

## 四、计费与 Usage 问题

### D123：Token 计费不一致

**严重级别：** P1 — 计费准确性  
**受影响模型（1 个）：** glm-4.5-air

**问题描述：** 报告的 `completion_tokens=500`，但实际内容仅 139 个本地 token（比率 3.6 倍）。用户可能为未交付的 token 支付了费用。

---

## 五、流式传输问题

### D111：流式响应过早终止

**严重级别：** P1  
**受影响模型（1 个）：** gpt-5.4-pro

**问题描述：** 流式响应在 0 个单词和无 `finish_reason` 的情况下终止，表明流被过早切断。

---

## 六、延迟与性能问题

### D91：人为延迟填充

**严重级别：** P1  
**受影响模型（1 个）：** glm-4.6

**问题描述：** 短请求的首 token 延迟（TTFT）为 4721ms，是长请求 TTFT（2000ms）的 2.4 倍，超过了 2.0 倍的阈值。简单请求不应比复杂请求耗时更长——此模式表明存在人为延迟填充。

---

### D99：限速响应缺少 Retry-After 头

**严重级别：** P1  
**受影响模型（1 个）：** glm-5-turbo

**问题描述：** 15 个请求中有 6 个收到了 429（限速）响应，但均未包含 `Retry-After` 头。客户端无法在缺少此指引的情况下实现正确的退避重试策略。

---

## 七、模型一致性问题

### D65：风格指纹不匹配

**严重级别：** P2  
**受影响模型（1 个）：** qwen3-coder-480b

**问题描述：** 写作风格距离（4.29）超过了与预期 Qwen 家族质心的阈值（4.0）。这可能表明模型的输出风格被代理修改，或者正在提供不同的模型变体。

---

## 附录：通过全部检测的模型（TIER_1）

以下 19 个模型通过了所有检测器，无实质问题：

| 模型 | 结果 |
|------|------|
| anthropic/claude-haiku-4-5 | TIER_1 |
| anthropic/claude-opus-4-5 | TIER_1 |
| anthropic/claude-opus-4-7 | TIER_1 |
| anthropic/claude-sonnet-4-5 | TIER_1 |
| anthropic/claude-sonnet-4-6 | TIER_1 |
| google/gemini-2.5-flash | TIER_1 |
| google/gemini-2.5-flash-image | TIER_1 |
| google/gemini-2.5-pro | TIER_1 |
| google/gemini-3.1-flash-lite-preview | TIER_1 |
| minimax/minimax-m2 | TIER_1 |
| minimax/minimax-m2.5 | TIER_1 |
| moonshotai/kimi-k2-thinking | TIER_1 |
| moonshotai/kimi-k2.6 | TIER_1 |
| qwen/qwen3.5-397b-a17b | TIER_1 |
| zai-org/glm-5-turbo | TIER_1 |
| anthropic/claude-opus-4-6 | TIER_1* |
| deepseek/deepseek-r1-0528 | TIER_1* |
| minimax/minimax-m2.1 | TIER_1* |
| minimax/minimax-m2.7 | TIER_1* |

\* 这些模型此前存在误报（已在最新代码中修复），重新测试后将确认 TIER_1 状态。

---

## 结论与建议

### 关键发现

1. **OpenAI 参数转发根本性缺失。** 全部 10 个 OpenAI 模型在 D62（logprobs）上失败，大多数同时在 D51（stop）、D68（frequency_penalty）、D70（logit_bias）上失败。这是系统性基础设施问题——Commonstack 的 OpenAI 路由管道似乎在转发至上游 API 前剥离或不转发这些标准参数。**建议：** 审计 OpenAI 请求转发路径，确保所有标准 `chat/completions` 参数被透传至上游 API。

2. **对 Grok 和 GLM-4.6 注入隐藏系统提示词。** Commonstack 在用户不知情的情况下，向 x-ai/grok 和 zai-org/glm-4.6 模型的请求中注入了 `<policy>` 安全系统提示词。虽然安全意图可能是合理的，但这违反了透明性原则——用户应被告知其请求被修改。**建议：** 在 API 文档中披露注入的安全层，或将其设为可选启用/关闭。

3. **DeepSeek 安全护栏被削弱。** DeepSeek v3.1 和 v3.2 遵从了 2/3 的普遍应被拒绝的有害提示（CSAM 相邻内容、针对性恶意软件）。结合 v3.1 上 D45 地址篡改的发现，Commonstack 上的 DeepSeek 模型存在较高的安全风险。**建议：** 调查 DeepSeek 模型是否有修改过的安全设置；考虑为这些模型添加安全层。

4. **跨供应商上下文截断。** 来自 4 个供应商（Google、OpenAI、Xiaomi、Zai-org）的 5 个模型出现上下文截断（D24a）。这表明 Commonstack 可能存在一个低于各模型实际支持的全局上下文长度限制。**建议：** 验证每个模型的上下文限制是否与上游供应商规格一致。

### 积极发现

- **Anthropic 模型全部满分** —— 6 个 Claude 模型全部为 TIER_1，零问题。Anthropic 路由管道是转发质量的标杆。
- **Minimax 模型表现优异** —— 4 个模型全部通过，无任何问题。
- **非参数依赖的检测器表现良好** —— 地址验证、工具调用完整性、会话隔离等核心安全检测在大多数模型上通过。

### 严重度分布

| 级别 | 数量 | 占比 |
|------|------|------|
| S0（严重 — 金融/安全） | 1 | 2% |
| P0（高 — API 合约违规） | 21 | 35% |
| P1（中 — 功能限制） | 38 | 63% |

大多数问题属于 P0/P1 级别的参数转发问题，可通过确保代理忠实转发所有标准 OpenAI API 参数至上游供应商来解决。
