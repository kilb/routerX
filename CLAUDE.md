# CLAUDE.md

## 项目概述

Router Auditor 是一个 LLM API Router 安全检测工具。通过 31 个 Detector 检测中转站（Router）的不诚实行为：模型替换、参数篡改、金融欺诈、网页逆向冒充等。

## 架构文档

开发前必须阅读以下两份文档：

1. **python_architecture_complete.md** — 完整架构设计，包含每个模块的代码模板
2. **admission_test_suite_fixed.md** — 31 个 Detector 的详细规格（请求 JSON、判定逻辑、PASS/FAIL 条件）

## 核心开发约束（必须遵守）

### 约束 1：实现前先厘清逻辑，建立整体认识

**在写任何一行代码之前**，先完整阅读 python_architecture_complete.md 和 admission_test_suite_fixed.md。理解：
- 31 个 Detector 之间的依赖关系（D29 依赖 D24a 的数据、D31 是预筛选）
- 5 个执行阶段的短路逻辑（S0 FAIL 后 P0/P1/P2 全部 SKIP）
- shared_context 的数据流向（哪些 Detector 写入、哪些读取）
- 条件执行的完整矩阵（哪些 Detector 在什么条件下 SKIP）

实现每个 Detector 时，先理解它在整个检测流程中的位置和职责，再动手写代码。不要孤立地实现单个 Detector。

### 约束 2：写代码前先思考最优实现

每个函数、每个类、每个判定逻辑，写之前先问自己：
- **这是不是最直接的实现？** 如果有更简洁的写法，用更简洁的。
- **数据结构选对了吗？** 例如用 set 做 O(1) 查找而不是 list 遍历。
- **有没有现成的库函数？** 不要手写已有库能做的事（如 `statistics.mean` 代替手写求平均）。
- **边界情况考虑了吗？** 空响应、None 值、网络错误、非预期格式。

如果对当前实现不确定是否最优，先写注释说明思路和备选方案，再实现。

### 约束 3：避免低效算法和冗余代码

- **不要复制粘贴。** 多个 Detector 共用的逻辑提取到 utils/ 或 BaseDetector。
- **不要嵌套超过 3 层的 if/for。** 超过了就提取函数。
- **不要在循环内做可以在循环外做的计算。**
- **字符串拼接用 join 或 f-string**，不要 `+=` 循环拼接。
- **JSON 解析用 ProbeResponse 的便捷属性**（`.content` / `.finish_reason` / `.tool_calls`），不要每个 Detector 重复写 `body["choices"][0]["message"]["content"]`。

示例——不要这样写：

```python
# ❌ 冗余：每个 Detector 都重复解析
content = ""
if resp.body and "choices" in resp.body:
    if len(resp.body["choices"]) > 0:
        msg = resp.body["choices"][0].get("message", {})
        content = msg.get("content", "")
```

应该这样写：

```python
# ✅ 简洁：用便捷属性
content = resp.content
```

### 约束 4：使用最新版本的库，选型必须 SOTA

当前项目的库选型已经过审查，是 2026 年 Python 生态的最优选择：

| 用途 | 库 | 最低版本 | 说明 |
|------|----|---------|----|
| HTTP | httpx | 0.27 | 唯一同时支持 sync/async + HTTP/2 |
| SSE | httpx-sse | 0.4 | httpx 生态唯一 SSE 库 |
| 验证 | pydantic | 2.0 | v2 性能比 v1 快 5-50× |
| Token | tiktoken | 0.7 | OpenAI 官方，Rust 后端 |
| 图片 | Pillow | 10.0 | 事实标准 |
| PDF | pymupdf | 1.24.2 | 读+写+渲染一体，C 后端极快 |
| CLI | rich | 13.0 | 事实标准 |
| API | fastapi | 0.110 | 事实标准 |
| ASGI | granian | 1.6 | Rust 后端，性能最优 |

**不要引入额外依赖。** 如果需要新功能，先确认现有依赖是否已覆盖。不要为了一个小功能引入整个库。

### 约束 5：代码实现要优雅

- **函数职责单一。** 一个函数做一件事。`send_probes()` 只发请求，`judge()` 只判定。
- **命名要自解释。** `beta_count` 不是 `cnt`，`is_network_error` 不是 `err_flag`。
- **用 early return 减少嵌套：**

```python
# ❌ 深嵌套
def judge(self, responses):
    r = responses[0]
    if not r.is_network_error:
        if r.status_code == 200:
            content = r.content
            if content:
                # ... 判定逻辑 ...

# ✅ early return
def judge(self, responses):
    r = responses[0]
    if r.is_network_error:
        return self._inconclusive(r.error)
    if r.status_code != 200:
        return self._inconclusive(f"status {r.status_code}")
    content = r.content
    if not content:
        return self._inconclusive("empty content")
    # ... 判定逻辑 ...
```

- **用列表推导替代简单循环：**

```python
# ❌
results = []
for r in responses:
    if r.is_network_error:
        results.append(r)
# ✅
net_errors = [r for r in responses if r.is_network_error]
```

- **用 dataclass/pydantic 替代裸 dict：** 项目中的所有数据结构已用 pydantic 定义，不要返回未定义的裸 dict。

- **魔法数字用常量：**

```python
# ❌
if beta_count < 400:
# ✅
MIN_EXPECTED_BETAS = 400
if beta_count < MIN_EXPECTED_BETAS:
```

### 约束 6：测试要充分

**每个 Detector 必须有 `_test_cases()`**，覆盖以下场景：

1. **PASS 场景**：正常输入，预期通过
2. **FAIL 场景**：触发检测的异常输入
3. **边界场景**：空响应、非预期格式、部分字段缺失
4. **网络错误场景**：`ProbeResponse(status_code=0, error="TIMEOUT")`

最少 3 个 test case。判定逻辑复杂的 Detector（如 D21 有 4 个子探针）需要更多：

```python
@classmethod
def _test_cases(cls):
    return [
        # 正常 PASS
        ("PASS: all normal", [...], "pass"),
        # 核心 FAIL
        ("FAIL: main detection", [...], "fail"),
        # 边界：空内容
        ("INCONCLUSIVE: empty content", 
         [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": ""}}]})],
         "inconclusive"),
        # 边界：非预期格式
        ("INCONCLUSIVE: malformed body",
         [ProbeResponse(status_code=200, body={"unexpected": True})],
         "inconclusive"),
    ]
```

**实现完一个 Detector 后立即自测**，确认全部 case 通过再进入下一个：

```bash
python -m src.detectors.d25_output_cap
# 必须看到 ✅ D25: N/N passed 才能继续
```

**不要跳过自测。** 不要攒多个 Detector 一起测。逐个实现、逐个验证。

---

## 开发顺序

严格按此顺序实现，每步完成后验证再进入下一步：

```
步骤 1-10：基础设施（models → client → tokenizer → assets → config → utils → events → registry → runner → reporter）
步骤 11-17：31 个 Detector（从最简单的 D25 开始，逐个实现）
步骤 18-20：API 层 + 集成测试
```

## 编码约定

### Python 版本与风格

- Python 3.11+，使用 `from __future__ import annotations`
- 类型标注：全部函数必须有参数和返回值类型标注
- 字符串：使用双引号 `"`，f-string 用于拼接
- import 顺序：标准库 → 第三方 → 项目内，各组之间空行分隔

### 代码语言：全英文

**代码中不允许出现任何中文，没有例外**，包括：

- ❌ 注释不要中文：`# 检查网络错误` → ✅ `# Check network errors`
- ❌ 日志不要中文：`logger.info("开始检测")` → ✅ `logger.info("Starting detection")`
- ❌ 错误信息不要中文：`self._fail("会话串线")` → ✅ `self._fail("cross-session leakage")`
- ❌ docstring 不要中文：`"""检测转账地址篡改"""` → ✅ `"""Detect transfer address tampering"""`
- ❌ 探针 prompt 不要中文：`"请介绍一下人工智能的发展历史。"` → ✅ `"Describe the history of artificial intelligence."`
- ❌ 变量名不要中文拼音：`jiance_jieguo` → ✅ `detection_result`

规格文档（01-04）中的中文 prompt 是设计说明，实现时全部翻译为英文。

```python
# ❌ 错误
class D28_SessionCrosstalkProbe(BaseDetector):
    description = "检测逆向池跨用户会话串线"
    
    async def send_probes(self):
        return [await self.client.send(ProbeRequest(
            payload={"messages": [{"role": "user", "content": "记住我的绝密内部代号是 GALAXY_99。只回复 OK。"}]},
            ...))]

# ✅ 正确
class D28_SessionCrosstalkProbe(BaseDetector):
    description = "Detect cross-session leakage in reverse proxy pool"
    
    async def send_probes(self):
        return [await self.client.send(ProbeRequest(
            payload={"messages": [{"role": "user", "content": "Remember my secret code is GALAXY_99. Reply only OK."}]},
            ...))]
```

### 文件大小

- 每个 Detector 文件 **< 200 行**
- 如果超过 200 行，拆分 helper 函数到 utils/

### 命名规范

- Detector 文件名：`d{编号}_{snake_case}.py`，如 `d28_session_crosstalk.py`
- Detector 类名：`D{编号}_{PascalCase}`，如 `D28_SessionCrosstalkProbe`
- detector_id：`"D28"`（字符串，与文档一致）

### 依赖使用

- HTTP 请求：**只用 httpx**，不用 requests/aiohttp/urllib
- SSE 解析：**只用 httpx-sse 的 aconnect_sse**，不要手写 SSE 解析
- PDF：**只用 pymupdf**，import 写 `import pymupdf` 不是 `import fitz`
- Token 计数：**只用 tiktoken**
- 图片：**只用 Pillow**
- 数据验证：**只用 pydantic v2**
- 音频：**用系统 TTS（espeak/say）**，不用 pydub/gTTS/numpy，不可用时 SKIP
- ETH 地址：**用 utils/eth.py**，不用 eth-account

### 禁止事项

- ❌ 不要在代码中写中文（注释、日志、错误信息、docstring 全部英文）
- ❌ 不要使用 `import fitz`，用 `import pymupdf`
- ❌ 不要安装 pydub、gTTS、numpy、eth-account
- ❌ 不要在 judge() 中做网络请求
- ❌ 不要在 Detector 中直接 `print()`，用 `logger`
- ❌ 不要 `from src.registry import _REGISTRY`（私有变量）
- ❌ 不要用 `hash()` 做缓存 key
- ❌ 不要硬编码 API endpoint path，用 `self.config.default_endpoint_path`
- ❌ 不要硬编码认证方式，`self.client` 已经处理了

## Detector 实现模式

### 模板

每个 Detector 必须遵循这个结构：

```python
from __future__ import annotations
from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult, Capability, ProviderType

@detector
class D{编号}_{名称}(BaseDetector):
    # === 必须声明的类变量 ===
    detector_id = "D{编号}"
    detector_name = "{名称}"
    priority = Priority.{S0|P0|P1|P2|PRE_SCREEN}
    judge_mode = JudgeMode.{ONCE|MAJORITY_2_OF_2|RELATIVE}
    request_count = {预估请求数}
    description = "{一句话描述}"
    
    # === 可选类变量（仅需要时声明）===
    # detector_timeout = 120.0                       # 默认 30s
    # required_capabilities = [Capability.VISION]    # 默认 [TEXT]
    # required_provider = ProviderType.OPENAI        # 默认 ANY
    # requires_direct = True                         # 默认 False
    # requires_single_route_claim = True             # 默认 False
    # depends_on = ["D24a"]                          # 默认 []

    async def send_probes(self) -> list[ProbeResponse]:
        """发送探针请求。只做 I/O，不做判定。"""
        return [await self.client.send(ProbeRequest(
            payload={...},
            endpoint_path=self.config.default_endpoint_path,
            description="...",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        """纯函数判定。不做网络请求。"""
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error)
        # ... 判定逻辑 ...
        if 失败条件:
            return self._fail("原因", {"key": "value"})
        return self._pass({"key": "value"})

    @classmethod
    def _test_cases(cls):
        """自测用例。返回 [(name, mock_responses, expected_verdict), ...]"""
        return [
            ("PASS case",
             [ProbeResponse(status_code=200, body={...})],
             "pass"),
            ("FAIL case",
             [ProbeResponse(status_code=200, body={...})],
             "fail"),
        ]

if __name__ == "__main__":
    D{编号}_{名称}.self_test()
```

### 判定模式选择

| 情况 | judge_mode | 说明 |
|------|-----------|------|
| 结果有唯一正确答案（nonce 匹配、token 计数、JSON schema） | ONCE | 1 次即判 |
| 受模型随机性影响（负面约束、图片识别、音频转录） | MAJORITY_2_OF_2 | 基类自动跑 2 次，都 FAIL 才判 FAIL |
| 需要直连 Provider 对比（金额、语义否定） | RELATIVE | 在 judge() 中自行处理有/无直连两种情况 |

### 网络错误处理

**不需要在 judge() 中检查网络错误**——基类 `_execute()` 已经统一处理了"全部请求都网络失败"的情况，直接返回 INCONCLUSIVE。

但如果 Detector 发了多个请求且部分失败（如 D28 的 10 个并发中 1-2 个失败），仍需在 judge() 中处理部分失败：

```python
def judge(self, responses):
    # 第 10 个是探测请求，前 9 个失败无所谓
    extract = responses[9]
    if extract.is_network_error:
        return self._inconclusive(extract.error)
    # ... 正常判定 ...
```

### 使用 ProbeResponse 的便捷属性

```python
r = responses[0]
r.content          # 自动解析 OpenAI/Anthropic/Gemini 三种格式
r.finish_reason    # 自动解析多种格式
r.tool_calls       # OpenAI tool calls 列表
r.usage            # usage dict
r.is_network_error # status_code == 0
r.headers          # response headers dict
r.raw_text         # 原始响应文本
```

### 需要直连 Provider 的 Detector

使用 `self.make_direct_client()` 创建直连客户端，它会自动使用正确的认证方式：

```python
async def send_probes(self):
    router_resps = [await self.client.send(p) for p in probes]
    direct_resps = []
    if self.has_direct:
        async with self.make_direct_client() as dc:
            direct_resps = [await dc.send(p) for p in probes]
    return router_resps + direct_resps

def judge(self, responses):
    n = len(probes)
    router_resps = responses[:n]
    direct_resps = responses[n:]  # 可能为空
    if direct_resps:
        # 有直连：做相对比较
        ...
    else:
        # 无直连：用绝对阈值，降低置信度
        return self._fail_degraded("reason", {...})
```

### 使用 shared_context

D29 需要 D24a 的数据：

```python
def judge(self, responses):
    d24a = self.shared.get("D24a")
    if d24a:
        # 使用 D24a 的结果
        prompt_text = d24a["evidence"].get("prompt_text", "")
    else:
        # fallback：使用当前请求的数据
        ...
```

### 使用 assets

```python
from ..assets import get_probe_image, get_probe_pdf, get_probe_audio, to_data_url, to_base64

# 图片
img_bytes, code = get_probe_image()
data_url = to_data_url(img_bytes, "image/png")

# PDF
pdf_bytes, nonce = get_probe_pdf()
b64 = to_base64(pdf_bytes)

# 音频
audio_bytes, text = get_probe_audio()
b64 = to_base64(audio_bytes)
```

### 使用 tokenizer

```python
from ..tokenizer import token_counter

count = token_counter.count("hello world", model="gpt-4o")
token_id = token_counter.get_token_id(" the", model="gpt-4o")
word, tid = token_counter.find_single_token([" the", " a", " is"])
tokens = token_counter.tokenize("hello world")
```

### 条件执行

Detector 只需声明类变量，跳过逻辑由基类自动处理：

```python
# 仅视觉渠道执行
required_capabilities = [Capability.VISION]

# 仅 Anthropic 执行
required_provider = ProviderType.ANTHROPIC

# 仅 OpenAI 执行
required_provider = ProviderType.OPENAI

# 仅声称单一 provider 时执行
requires_single_route_claim = True

# 仅当有 task_model 能力时执行
required_capabilities = [Capability.TASK_MODEL]
```

不匹配时自动返回 SKIP，不需要在 send_probes() 或 judge() 中检查。

## 验证方式

### 单个 Detector 自测

```bash
python -m src.detectors.d25_output_cap
# 输出：
#   ✅ PASS: 800 betas
#   ✅ FAIL: capped
# ✅ D25: 2/2 passed
```

### 批量自测

```bash
python scripts/self_test_all.py
```

### 端到端测试（用 mock server）

```bash
# 终端 1：启动 mock server
uvicorn tests.mock_server:app --port 8999

# 终端 2：跑检测
python -m scripts.admission_test \
  --endpoint http://localhost:8999/v1 \
  --api-key test-key \
  --only D25 D28
```

### API 测试

```bash
# 启动 API
AUDITOR_API_KEY=test python -m scripts.serve --port 8900

# 创建任务
curl -X POST http://localhost:8900/api/v1/tests \
  -H "Authorization: Bearer test" \
  -H "Content-Type: application/json" \
  -d '{"router_endpoint":"http://localhost:8999/v1","api_key":"test"}'
```

## 常见错误及修复

| 错误 | 原因 | 修复 |
|------|------|------|
| `ModuleNotFoundError: fitz` | 用了旧 import 名 | 改为 `import pymupdf` |
| `ProbeResponse has no field 'content'` | content 是 @property 不是字段 | 直接用 `r.content` 不要 `r.body["choices"]...` |
| Detector 没被注册 | 文件名不以 `d` 开头 | 确保文件名是 `d{编号}_{name}.py` |
| `_REGISTRY is empty` | 忘了 `import src.detectors` | 在入口脚本顶部加 `import src.detectors  # noqa: F401` |
| judge() 崩溃 | body 为 None 时直接取字段 | 用 `r.content` / `r.finish_reason` 便捷属性 |
| 429 报错 | 请求太快 | client.py 已有速率控制，不需要额外处理 |
| FAIL 但实际是模型随机性 | 非确定性 Detector 用了 ONCE | 改为 MAJORITY_2_OF_2 |
| Anthropic 渠道 401 | 用了 Bearer 认证 | 声明 `auth_method = "x-api-key"` |

## 53 个 Detector 的条件依赖速查

| Detector | provider | capability | direct | single_route | 判定模式 |
|----------|----------|-----------|--------|-------------|---------|
| D31 | any | text | - | - | once |
| D28 | any | text | - | - | once |
| D47 | any | text | - | - | once |
| D48 | any | text | ✅ 可选 | - | relative |
| D45 | any | text | - | - | once |
| D21 | any | text | - | - | ≥2/4 子探针 |
| D22a | openai | text | - | - | once |
| D22b | anthropic | text | - | - | once |
| D22c | anthropic | text | - | - | once |
| D22d | any | text | - | - | once |
| D22e | any | text | - | ✅ 必须 | once |
| D23 | any | text | - | - | once |
| D30 | any | text | - | - | once |
| D50 | any | text | ✅ 可选 | - | once/降级 |
| D4a | any | text | - | - | once |
| D4b | any | text | - | - | 2/2 |
| D16b | any | text | - | - | once |
| D24a | any | text | - | - | once |
| D24b | any | text | - | - | once |
| D25 | any | text | - | - | once |
| D29 | any | text | - | - | once |
| D26 | any | text | - | - | once |
| D38 | openai | text | - | - | once |
| D54 | any | text | - | - | 2/2 |
| D27 | any | vision | - | - | 2/2 |
| D27b | any | pdf | - | - | once |
| D27c | any | vision | - | - | 2/2 |
| D27d | any | audio | - | - | 2/2 |
| D32a | any | text | - | - | once |
| D55 | any | task_model | - | - | once |
| D15 | any | text | - | - | once |
| D37 | any | text | - | - | once |
| D11 | any | text | - | - | once |
| D53 | any | text | ✅ 可选 | - | once/降级 |
| D42 | any | text | - | - | once |
| D43 | any | text | - | - | once |
| D44 | any | text | - | - | 2/2 |
| D51 | any | text | - | - | once |
| D52 | any | text | - | - | once |
| D56 | any | tool_calling | - | - | once |
| D57 | any | text | - | - | once |
| D59 | any | text | - | - | once |
| D60 | any | text | - | - | 2/2 |
| D61 | any | text | - | - | 2/2 |
| D62 | any | text | - | - | once |
| D64 | any | text | - | - | once |
| D65 | any | text | - | - | 2/2 |
| D68 | any | text | - | - | 2/2 |
| D70 | any | text | - | - | once |
