# 准入测试套件总览

## 执行参数

- **Detector 数：** 31（+ 1 预筛选）
- **总请求：** 约 69
- **总耗时：** 约 275 秒
- **总成本：** 约 $0.68（GPT-4o 基准）

## 测试前提

1. 固定模型别名（如 gpt-4o / claude-sonnet），关闭 fallback / retry / cache / 自动降级
2. 回传 route-id 或 upstream-id（可选）
3. 全部请求保留：原始请求/响应 JSON、全部 headers、stream 每个 chunk 时间戳+内容

## 优先级定义

| 等级 | 含义 | 触发动作 |
|------|------|---------|
| S0 | 不可逆损害（资金损失 / 跨用户数据泄露） | 永久拉黑 |
| P0 | 严重违规（底层伪装 / 注入 / 模型顶包 / 工具降级） | 拉黑 |
| P1 | 质量违规（截断 / 缓存 / 多模态降级 / 假流式） | 降级标记 Tier 2 |
| P2 | 一般违规（安全护栏 / 特性剥离） | 警告 |

## 判定机制

| 类型 | 规则 | 适用 Detector |
|------|------|-------------|
| 确定性（唯一正确答案） | 1 次即判 | D28, D45, D47, D16b, D22, D23, D24a, D24b, D25, D26, D29, D30, D32a |
| 非确定性（受模型随机性） | 2/2 多数判定（都 FAIL 才判 FAIL） | D4b, D21a, D54, D27, D27c, D27d |
| 相对比较（需基线/直连） | Router vs 直连差分 | D21d, D48, D50, D53 |

## 威胁覆盖

| 类别 | Detector |
|------|---------|
| A. Reverse/浏览器自动化 | D21, D22, D23, D28, D30, D31 |
| B. 多跳/路由切换 | D30, D38, D22e |
| C. Middleware/Prompt 注入 | D11, D15, D16b, D22, D29, D31, D45, D50 |
| D. 模型洗牌/冒名 | D4a, D4b, D31, D22e |
| E. 缓存/截断 | D24a, D24b, D25, D26, D32a, D38, D54 |
| F. 多模态降级 | D27, D27b, D27c, D27d |
| G. 异步任务伪造 | D55 |
| I. 参数篡改 | D45, D47, D48 |

## 执行编排

```
阶段 0 — 预筛选（5s）
└─ D31 GodPayload                1 请求    5s
    ↓ 无论结果都继续

阶段 1 — S0（约 45s）
├─ D28 SessionCrosstalk         10 并发    5s
├─ D47 AddressConsistency        3 请求   10s
├─ D48 AmountPrecision           6 请求   15s
└─ D45 ToolCallArgVerifier       3 请求   10s
    ↓ 全 PASS（任一 FAIL → 后续全 SKIP）

阶段 2 — P0（约 85s）
├─ D21 PhysicalParamProbe        5 请求   15s
├─ D22 ProtocolStrictness        4 请求   15s
├─ D23 HijackedTokenProbe        2 请求    5s
├─ D30 ErrorPathForensics        3 请求   10s
├─ D50 SemanticNegationCheck     2 请求   10s
├─ D4a TokenizerFingerprint      1 请求    5s
├─ D4b NegativeConstraintProbe   2 请求   10s
├─ D16b ToolCallingProbe         1 请求    5s
└─ D22e CrossProtocolContradict  1 请求    5s
    ↓ 全 PASS（任一 FAIL → 后续全 SKIP）

阶段 3 — P1（约 115s）
├─ D24a 夹心饼干                  1 请求   10s
├─ D24b 分布式代数锁              1 请求   15s
├─ D25 OutputCapProbe             1 请求    5s
├─ D29 UsageBillAuditor           0 请求    0s
├─ D26 SemanticCacheBuster        2 请求   10s
├─ D38 SeedReproducibility        3 请求   10s
├─ D54 TaskCompletionProbe        2 请求   10s
├─ D27 ImageFidelityProbe         2 请求   10s
├─ D27b PDFFidelityProbe          1 请求   10s
├─ D27c MultiImageOrderProbe      2 请求   10s
├─ D27d AudioFidelityProbe        2 请求   10s
├─ D32a StreamingBasicProbe       1 请求   10s
└─ D55 AsyncTaskProbe             2+poll  30s
    ↓ 不短路

阶段 4 — P2（约 25s）
├─ D15 GuardrailIntegrity         1 请求    5s
├─ D37 StopSeqProbe               1 请求    5s
├─ D11 RequestIntegrity           1 请求    5s
└─ D53 MetadataCompleteness       2 请求   10s
    ↓ 不短路
    ✓ 准入通过
```

## 速查表

| # | Detector | 级别 | 请求 | 条件 | 判定 | 威胁 |
|---|---------|------|------|------|------|------|
| D31 | GodPayload | 预筛 | 1 | 全部 | 预警 | A/C/D/E |
| D28 | SessionCrosstalk | S0 | 10并发 | 全部 | 1次 | A |
| D47 | AddressConsistency | S0 | 3 | 全部 | 1次 | I |
| D48 | AmountPrecision | S0 | 6 | 全部(直连可选) | 相对 | I |
| D45 | ToolCallArgVerifier | S0 | 3 | 全部 | 1次 | I/C |
| D21 | PhysicalParamProbe | P0 | 5 | 全部 | ≥2fail | A |
| D22 | ProtocolStrictness | P0 | 4 | 按provider | 任一fail | A/D |
| D23 | HijackedTokenProbe | P0 | 2 | 全部 | 1次 | A |
| D30 | ErrorPathForensics | P0 | 3 | 全部 | 1次 | A/B |
| D50 | SemanticNegation | P0 | 2/1 | 全部(直连可选) | 1次/降级 | C |
| D4a | TokenizerFingerprint | P0 | 1 | 全部 | 1次 | D |
| D4b | NegativeConstraint | P0 | 2 | 全部 | 2/2 | D |
| D16b | ToolCallingProbe | P0 | 1 | 全部 | 1次 | C |
| D22e | CrossProtocolContra | P0 | 1 | 声称单一provider | 1次 | B/D |
| D24a | 夹心饼干 | P1 | 1 | 全部 | 1次 | E |
| D24b | 分布式代数锁 | P1 | 1 | 全部 | 1次 | E |
| D25 | OutputCapProbe | P1 | 1 | 全部 | 1次 | C |
| D29 | UsageBillAuditor | P1 | 0 | 全部 | 1次 | C |
| D26 | SemanticCacheBuster | P1 | 2 | 全部 | 1次 | E |
| D38 | SeedReproducibility | P1 | 3 | 仅OpenAI | 1次 | B |
| D54 | TaskCompletion | P1 | 2 | 全部 | 2/2 | E |
| D27 | ImageFidelityProbe | P1 | 2 | 仅视觉 | 2/2 | F |
| D27b | PDFFidelityProbe | P1 | 1 | 仅PDF | 1次 | F |
| D27c | MultiImageOrder | P1 | 2 | 仅视觉 | 2/2 | F |
| D27d | AudioFidelityProbe | P1 | 2 | 仅音频 | 2/2 | F |
| D32a | StreamingBasicProbe | P1 | 1 | 全部 | 1次 | E |
| D55 | AsyncTaskProbe | P1 | 2+poll | 仅task model | 1次 | G |
| D15 | GuardrailIntegrity | P2 | 1 | 全部 | 1次 | C |
| D37 | StopSeqProbe | P2 | 1 | 全部 | 1次 | C |
| D11 | RequestIntegrity | P2 | 1 | 全部 | 1次 | C |
| D53 | MetadataCompleteness | P2 | 2/1 | 全部(直连可选) | 1次/降级 | C |
