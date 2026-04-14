# 阶段 3 P1 质量违规 — 完整规格（13 个 Detector）

FAIL → 降级标记 Tier 2，不拉黑，不短路。

---

### D24a: ContextTruncationProbe 夹心饼干

**检测目标：** M29 上下文恶意截断（10k token 级别）

**请求数：** 1 | **耗时：** ~10s | **成本：** ~$0.03 | **判定：** 1 次即判 | **条件：** 全部

**实现：**

用 Python 生成 300 个对象的 JSON 数组（约 10k token），在三个位置硬插入 canary：

```python
data = []
for i in range(300):
    obj = {"id": i, "value": f"filler_text_{i}_" + "x" * 30}
    if i == 10:
        obj["canary"] = "[CANARY_HEAD: ALPHA-11]"
    elif i == 150:
        obj["canary"] = "[CANARY_MID: BETA-22]"
    elif i == 290:
        obj["canary"] = "[CANARY_TAIL: GAMMA-33]"
    data.append(obj)
```

```json
{
  "model": "<claimed_model>",
  "max_tokens": 200,
  "messages": [
    {"role": "user", "content": "<上述 JSON 字符串>\n\nPlease exactly output the three CANARY passwords hidden in the JSON."}
  ]
}
```

**判定：**

| 输出结果 | 判定 |
|---------|------|
| 3 个密码全部正确（ALPHA-11, BETA-22, GAMMA-33） | **PASS** |
| HEAD + TAIL 正确，MID 缺失 | **P1 FAIL**（截断实锤） |
| 密码全乱或模型幻觉 | **P1 FAIL**（降智实锤） |

**额外操作：** 将 prompt 文本和响应 usage 存入 shared_context，供 D29 复用。

---

### D24b: ContextTruncationProbe 分布式代数锁

**检测目标：** M29 上下文截断（80k token 级别，专测 128k 长上下文）

**请求数：** 1 | **耗时：** ~15s | **成本：** ~$0.20 | **判定：** 1 次即判 | **条件：** 全部

**实现：**

构造约 80k token 文本，用分散的代数变量替代 UUID（防网关正则提取保留）。填充量应根据目标模型的 tokenizer 动态计算，不要固定重复次数：

```python
from src.tokenizer import token_counter

target_tokens = 80000  # 目标 token 数
filler_sentence = "The quick brown fox jumps over the lazy dog. "

# 动态计算需要多少次重复
tokens_per_sentence = token_counter.count(filler_sentence, model=claimed_model)
repeats = target_tokens // max(tokens_per_sentence, 1)
filler = filler_sentence * repeats

# 插入变量（按字符位置近似，从后往前避免偏移）
# var_X 在 ~2k token 处（约 8k 字符）
# var_Y 在 ~40k token 处（约 160k 字符）— 最易被截断的中部
# var_Z 在 ~78k token 处（约 312k 字符）
text = filler
for char_pos, var_line in sorted([
    (8000, "\nvar_X = 14\n"),
    (160000, "\nvar_Y = 5\n"),
    (min(312000, len(filler) - 100), "\nvar_Z = 2\n"),
], reverse=True):
    pos = min(char_pos, len(text))
    text = text[:pos] + var_line + text[pos:]
```

```json
{
  "model": "<claimed_model>",
  "max_tokens": 50,
  "messages": [
    {"role": "user", "content": "<上述 80k 文本>\n\n不要总结，直接输出 (var_X + var_Y) * var_Z 的结果。"}
  ]
}
```

**判定：**

| 输出结果 | 判定 |
|---------|------|
| 38（正确：(14+5)×2=38） | **PASS** |
| 其他数字或 "无法找到变量" | **P1 FAIL**（中部 var_Y 被截断） |

---

### D25: OutputCapProbe — 输出长度锁喉检测器

**检测目标：** M30 输出长度暗锁

**请求数：** 1 | **耗时：** ~5s | **判定：** 1 次即判 | **条件：** 全部

```json
{
  "model": "<claimed_model>",
  "max_tokens": 2048,
  "messages": [
    {"role": "user", "content": "请重复输出单词 'BETA' 正好 800 次，中间用空格隔开。不要输出任何其他内容。"}
  ]
}
```

**判定：**

| 结果 | 判定 |
|------|------|
| beta_count ≥ 700 且 finish_reason == "stop" | **PASS** |
| beta_count < 400 且 finish_reason == "length" | **P1 FAIL**（Router 暗中降低 max_tokens） |
| beta_count < 400 且 finish_reason == "stop" | **P1 FAIL**（语义截断 M59） |

---

### D29: UsageBillAuditor — 阴阳账本审计器

**检测目标：** M34 阴阳账本（截断内容但按全量收费）

**请求数：** 0（复用 D24a 数据）| **耗时：** 0s | **判定：** 1 次即判 | **条件：** 全部 | **depends_on：** D24a

**实现：**

复用 D24a 的请求和响应（从 shared_context 中获取）。本地用 tiktoken 精确计算 prompt token 数，对比 Router 返回的 `usage.prompt_tokens`。

**D24a 不可用时的 fallback：** 发 1 个轻量请求（重复文本，约 500 token），独立做 token 计数比对。

**判定：**

| D24a 结果 | usage 偏差 | 判定 |
|-----------|-----------|------|
| PASS | < 5% | **PASS** |
| PASS | > 10% | **P1 FAIL**（token 虚报） |
| FAIL（截断） | < 5% | **P1 FAIL**（阴阳账本：内容截断但 usage 按全量报） |

---

### D26: SemanticCacheBuster — 语义缓存击穿检测器

**检测目标：** M31 语义缓存欺诈

**请求数：** 2 | **耗时：** ~10s | **判定：** 1 次即判 | **条件：** 全部

**实现：**

连续发送两个语义相似但包含不同动态标记的请求：

请求 A：
```json
{
  "model": "<claimed_model>",
  "temperature": 0,
  "max_tokens": 120,
  "messages": [
    {"role": "user", "content": "Write Python quicksort. Put this exact nonce in the first comment line: CACHE-A-20260413-090101"}
  ]
}
```

请求 B（1-3 秒后发）：
```json
{
  "model": "<claimed_model>",
  "temperature": 0,
  "max_tokens": 120,
  "messages": [
    {"role": "user", "content": "Write Python quicksort. Put this exact nonce in the first comment line: CACHE-B-20260413-090104"}
  ]
}
```

**判定：**

| 结果 | 判定 |
|------|------|
| 请求 B 输出包含 CACHE-B | **PASS** |
| 请求 B 输出包含 CACHE-A | **P1 FAIL**（语义缓存重放） |
| 两次返回完全一致（逐字节相同） | **P1 FAIL**（高度疑似缓存） |

---

### D38: SeedReproducibility — Seed 可复现性检测器

**检测目标：** M41 Seed 参数忽略

**请求数：** 3 | **耗时：** ~10s | **判定：** 1 次即判 | **条件：** 仅 OpenAI 渠道

Claude/Anthropic API 没有 seed 参数，Gemini 行为不同。非 OpenAI 渠道自动 SKIP。

```json
{
  "model": "<claimed_model>",
  "seed": 42,
  "temperature": 0,
  "max_tokens": 100,
  "messages": [
    {"role": "user", "content": "用 Python 写一个计算斐波那契数列第 10 项的函数。"}
  ]
}
```

发 3 次完全相同请求。

**判定：**

```python
# 3 次结果两两比较
from itertools import combinations
pairs = list(combinations([r.content for r in responses], 2))
matching = sum(1 for a, b in pairs if a == b)
```

- 至少 1 对完全一致（matching ≥ 1）→ **PASS**（seed 生效，允许偶发不一致）
- 3 次全不同（matching == 0）→ **P1 FAIL**（seed 被忽略）

---

### D54: TaskCompletionProbe — 任务完成度探针

**检测目标：** M59 语义边界截断

**请求数：** 2 | **耗时：** ~10s | **判定：** 2/2 多数判定 | **条件：** 全部

```json
{
  "model": "<claimed_model>",
  "max_tokens": 2000,
  "messages": [
    {"role": "user", "content": "请列出 20 种编程语言及其主要用途，每种一行。在完成全部 20 种后，在最后一行输出 '[LIST_COMPLETE]'。"}
  ]
}
```

**判定：**
- ≥ 20 种 + [LIST_COMPLETE] + finish_reason=stop → PASS
- < 15 种 + 无 [LIST_COMPLETE] + finish_reason=stop → FAIL（语义截断）
- < 15 种 + finish_reason=length → FAIL（粗暴截断）
- 2/2 都 FAIL → **P1 FAIL**

---

### D27: ImageFidelityProbe — 图片保真度检测器

**检测目标：** M32 多模态压缩降级

**请求数：** 2 | **耗时：** ~10s | **判定：** 2/2 多数判定 | **条件：** 仅视觉渠道

**实现：**

生成 4000×4000 纯白背景图片，右下区域 (3800,3800) 用 16px 中灰 (120,120,120) 字体写 6 位随机验证码。

```python
from PIL import Image, ImageDraw, ImageFont
import random, string

code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
img = Image.new('RGB', (4000, 4000), 'white')
draw = ImageDraw.Draw(img)
font = ImageFont.truetype("DejaVuSans.ttf", 16)
draw.text((3800, 3800), code, fill=(120, 120, 120), font=font)
```

```json
{
  "model": "<claimed_model>",
  "temperature": 0,
  "max_tokens": 20,
  "messages": [
    {
      "role": "user",
      "content": [
        {"type": "image_url", "image_url": {"url": "data:image/png;base64,<B64>", "detail": "high"}},
        {"type": "text", "text": "这张图片的右下角有一行极小的文字验证码。请精确读出验证码，只输出验证码本身。"}
      ]
    }
  ]
}
```

**判定：**
- 精确输出验证码 → PASS
- 错误验证码 → FAIL（图片被压缩，16px 字变模糊）
- "没有看到文字" → FAIL（图片被严重压缩或替换）
- 2/2 都 FAIL → **P1 FAIL**

**原理：** 原厂 `detail: "high"` 将图片按 Tiles 切片送入模型，能识别 16px 字符。Router 压缩 4000→512 后，16px 变成 ~2px，物理不可读。

---

### D27b: PDFFidelityProbe — PDF 保真度探针

**检测目标：** PDF 多模态降级

**请求数：** 1 | **耗时：** ~10s | **判定：** 1 次即判 | **条件：** 仅 PDF 渠道

**实现：**

生成 3 页 PDF（用 pymupdf）：
- 第 1 页：无关填充文本
- 第 2 页：页眉写 `PDF-NONCE-MID-55K`，正文无关内容
- 第 3 页：无关填充文本

```json
{
  "model": "<claimed_model>",
  "temperature": 0,
  "max_tokens": 40,
  "messages": [
    {
      "role": "user",
      "content": [
        {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": "<PDF_B64>"}},
        {"type": "text", "text": "Read the PDF. Output only the nonce found on page 2. Nothing else."}
      ]
    }
  ]
}
```

**判定：**
- 精确输出 `PDF-NONCE-MID-55K` → **PASS**
- 错误 nonce / 来自其他页 → **P1 FAIL**（页码定位错乱）
- "无法读取 PDF" → **P1 FAIL**（PDF 处理被降级）
- 只看到第 1 页内容 → **P1 FAIL**（只处理了首页）

---

### D27c: MultiImageOrderProbe — 多图顺序完整性探针

**检测目标：** 多图支持伪造 / 图片顺序打乱

**请求数：** 2 | **耗时：** ~10s | **判定：** 2/2 多数判定 | **条件：** 仅视觉渠道

**实现：**

生成两张 800×200 图片：
- img1：画面大字写 `IMG-FIRST-93QK`
- img2：画面大字写 `IMG-SECOND-18LM`

```json
{
  "model": "<claimed_model>",
  "temperature": 0,
  "max_tokens": 20,
  "messages": [
    {
      "role": "user",
      "content": [
        {"type": "text", "text": "Output only the nonce from the SECOND image. Nothing else."},
        {"type": "image_url", "image_url": {"url": "data:image/png;base64,<img1_B64>"}},
        {"type": "image_url", "image_url": {"url": "data:image/png;base64,<img2_B64>"}}
      ]
    }
  ]
}
```

**判定：**
- `IMG-SECOND-18LM` → PASS
- `IMG-FIRST-93QK` → FAIL（顺序处理错误 / 只传第一张）
- "只看到一张图" → FAIL（多图降级为单图）
- 两个 nonce 混在一起 → FAIL
- 2/2 都 FAIL → **P1 FAIL**

---

### D27d: AudioFidelityProbe — 音频保真度探针

**检测目标：** 音频多模态降级（先走固定 ASR 再喂文本）

**请求数：** 2 | **耗时：** ~10s | **判定：** 2/2 多数判定 | **条件：** 仅音频渠道

**实现：**

生成包含 `CRIMSON FORTY TWO`（NATO 词汇）的真人语音 WAV。

**音频生成方式（三级 fallback，不需要人工录制）：**

```python
def generate_probe_audio(text="CRIMSON FORTY TWO"):
    import subprocess, tempfile
    from pathlib import Path

    # 1. Linux: espeak（大部分 Linux 发行版预装）
    try:
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
            subprocess.run(
                ["espeak", "-w", f.name, "-s", "130", text],
                check=True, capture_output=True, timeout=10,
            )
            return Path(f.name).read_bytes(), text
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass

    # 2. macOS: say + afconvert
    try:
        with tempfile.NamedTemporaryFile(suffix=".aiff", delete=False) as f:
            subprocess.run(["say", "-o", f.name, text],
                           check=True, capture_output=True, timeout=10)
            wav_path = f.name.replace(".aiff", ".wav")
            subprocess.run(["afconvert", "-f", "WAVE", "-d", "LEI16",
                           f.name, wav_path], check=True, capture_output=True)
            return Path(wav_path).read_bytes(), text
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass

    # 3. 都不可用 → 返回 None，Detector 自动 SKIP
    return None, text
```

**注意：** 如果系统没有 TTS 引擎（espeak/say 都不可用），D27d 自动 SKIP 而非用无意义的合成音调。`assets.py` 中原有的纯音调合成方案**已废弃**——多模态模型无法从频率序列中提取文字。

```json
{
  "model": "<claimed_model>",
  "temperature": 0,
  "max_tokens": 12,
  "messages": [
    {
      "role": "user",
      "content": [
        {"type": "text", "text": "Output only the verification nonce spoken in the audio. Nothing else."},
        {"type": "input_audio", "input_audio": {"data": "<WAV_B64>", "format": "wav"}}
      ]
    }
  ]
}
```

**判定：**
- `CRIMSON FORTY TWO` → PASS
- 近音变体（CRIMSON FOURTEEN / CRIMSON 42）→ FAIL（低质量 ASR 中间层）
- "无法处理音频" → FAIL
- 2/2 都 FAIL → **P1 FAIL**

**原理：** 原厂多模态 API 端到端处理音频。Router 如果先走 ASR（如 Whisper）再喂文本，NATO 词汇的 ASR 错误率显著高于端到端模型（尤其是 CRIMSON 容易被转录为 CHRISTMAS / CRIMSON 等变体）。

---

### D32a: StreamingBasicProbe — 流式基础探针

**检测目标：** Fake streaming（非流式结果切 chunk 伪装）

**请求数：** 1 | **耗时：** ~10s | **判定：** 1 次即判 | **条件：** 全部

```json
{
  "model": "<claimed_model>",
  "temperature": 0,
  "stream": true,
  "stream_options": {"include_usage": true},
  "max_tokens": 220,
  "messages": [
    {"role": "user", "content": "Output the numbers from 1 to 120, one per line, and nothing else."}
  ]
}
```

**记录指标：**
- TTFB（首 chunk 到达时间）
- chunk 数量
- 每个 chunk 的 token/字符数
- 最后是否有 usage block
- finish_reason

**判定：**

| 检查项 | 通过 | 失败 |
|--------|------|------|
| chunk 数量 | ≥ 10 个 | ≤ 2 个巨大 chunk |
| 内容分布 | 各 chunk 大小相对均匀 | 80%+ 集中在最后 1 个 chunk |
| usage 尾块 | stream 结尾有 usage block | 无 usage（如果请求了 include_usage） |
| finish_reason | 值合理（stop 或 length） | 缺失或异常 |

任一失败 → **P1 FAIL**

---

### D55: AsyncTaskProbe — 异步任务真伪探针

**检测目标：** 异步任务模型的任务伪造 / 本地假队列 / 缓存重放

**请求数：** 2 + poll | **耗时：** 30-120s | **判定：** 1 次即判 | **条件：** 仅 task model | **超时：** 120s

**实现：**

准备两个相似但 nonce 不同的任务 prompt：

任务 A（POST 创建）：
```json
{
  "model": "<task_model>",
  "prompt": "A red ball rolling on a white floor. Put visible text NONCE-A7M2 in the first frame.",
  "duration": 5
}
```

任务 B（5 秒后 POST 创建）：
```json
{
  "model": "<task_model>",
  "prompt": "A red ball rolling on a white floor. Put visible text NONCE-B8K5 in the first frame.",
  "duration": 5
}
```

提交后每 2 秒 GET 轮询任务状态（端点由 `task_model_config` 配置，`task_id_field` 指定从创建响应中提取 task_id 的字段名，默认 `"task_id"`，某些 API 可能用 `"id"` 或 `"job_id"`）。

**判定（元数据为主，内容验证为辅）：**

| 检查项 | 通过 | 失败 |
|--------|------|------|
| task_id | A 和 B 不同 | B 复用 A 的 → **P1 FAIL** |
| 状态流转 | queued → running → succeeded | 跳变异常 → **P1 FAIL** |
| 产物 | A 和 B 产物在像素级有差异 | 完全相同 → **P1 FAIL**（缓存重放） |
| nonce（加分） | A 含 A7M2，B 含 B8K5 | 不影响 PASS/FAIL |
