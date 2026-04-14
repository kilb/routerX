"""Pure-algorithmic probe asset generators (images / PDF / audio / payload).

Everything is cached in a process-local dict so repeated calls within a
test run reuse the same bytes. Audio generation has a three-level fallback:
espeak (Linux) > say+afconvert (macOS) > None (detector auto-SKIPs).
"""
from __future__ import annotations

import asyncio
import base64
import io
import json as json_mod
import random
import string
import subprocess
import tempfile
from pathlib import Path
from typing import Any

_asset_cache: dict[str, Any] = {}

_FONT_PATHS = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/System/Library/Fonts/Helvetica.ttc",
    "C:\\Windows\\Fonts\\arial.ttf",
]


# ---------- image ----------

def generate_probe_image(
    code: str | None = None,
    size: tuple[int, int] = (4000, 4000),
    font_size: int = 16,
    fill: tuple[int, int, int] = (120, 120, 120),
    position: tuple[int, int] = (3800, 3800),
) -> tuple[bytes, str]:
    """Generate a large white image with a small secret code near the corner.

    Used by D27 to force the model to resolve the tiny glyphs -- any
    router downscaling will hide the code.
    """
    from PIL import Image, ImageDraw

    if code is None:
        code = _random_code(6)
    img = Image.new("RGB", size, "white")
    draw = ImageDraw.Draw(img)
    draw.text(position, code, fill=fill, font=_get_font(font_size))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue(), code


def generate_nonce_image(text: str, size: tuple[int, int] = (800, 200)) -> bytes:
    from PIL import Image, ImageDraw

    img = Image.new("RGB", size, "white")
    draw = ImageDraw.Draw(img)
    draw.text((50, 70), text, fill=(0, 0, 0), font=_get_font(48))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# ---------- PDF ----------

def generate_probe_pdf(nonce: str = "PDF-NONCE-MID-55K") -> tuple[bytes, str]:
    """Three-page PDF whose middle page hides the nonce inside filler text."""
    import pymupdf

    doc = pymupdf.open()
    for page_num in range(3):
        page = doc.new_page(width=612, height=792)
        y = 72
        if page_num == 1:
            page.insert_text(
                (72, y), nonce, fontsize=16, fontname="helv", color=(0, 0, 0)
            )
            y += 30
        for i in range(20):
            page.insert_text(
                (72, y + i * 18),
                f"Filler content line {i+1} on page {page_num+1}.",
                fontsize=11, fontname="helv", color=(0.3, 0.3, 0.3),
            )
    pdf_bytes = doc.tobytes()
    verify = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    if nonce not in verify[1].get_text():
        verify.close()
        doc.close()
        raise RuntimeError(
            f"PDF self-check failed: nonce {nonce!r} missing from page 2"
        )
    verify.close()
    doc.close()
    return pdf_bytes, nonce


def generate_probe_pdf_with_image(nonce: str = "PDF-IMG-X9K2") -> tuple[bytes, str]:
    import pymupdf

    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), nonce, fontsize=14, fontname="helv")
    img_bytes = generate_nonce_image(f"IMG-IN-PDF-{_random_code(4)}")
    page.insert_image(pymupdf.Rect(72, 120, 400, 280), stream=img_bytes)
    pdf_bytes = doc.tobytes()
    doc.close()
    return pdf_bytes, nonce


def render_pdf_page_to_image(
    pdf_bytes: bytes, page_num: int = 0, dpi: int = 150
) -> bytes:
    import pymupdf

    doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    pix = doc[page_num].get_pixmap(dpi=dpi)
    img = pix.tobytes("png")
    doc.close()
    return img


def extract_pdf_text(pdf_bytes: bytes, page_num: int | None = None) -> str:
    import pymupdf

    doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    if page_num is not None:
        text = doc[page_num].get_text()
    else:
        text = "\n\n".join(p.get_text() for p in doc)
    doc.close()
    return text


# ---------- audio ----------

def generate_probe_audio(
    text: str = "CRIMSON FORTY TWO",
) -> tuple[bytes | None, str]:
    """Synthesize real speech via system TTS.

    Fallback order: espeak (Linux) > say + afconvert (macOS) > (None, text).
    When the return value is ``(None, text)`` the caller must SKIP -- no
    synthetic tone sequences are produced, multimodal models cannot
    transcribe them.
    """
    # 1. Linux: espeak
    try:
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
            tmp_path = f.name
        try:
            subprocess.run(
                ["espeak", "-w", tmp_path, "-s", "130", text],
                check=True, capture_output=True, timeout=10,
            )
            data = Path(tmp_path).read_bytes()
            return data, text
        finally:
            Path(tmp_path).unlink(missing_ok=True)
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass

    # 2. macOS: say + afconvert
    try:
        with tempfile.NamedTemporaryFile(suffix=".aiff", delete=False) as f:
            aiff_path = f.name
        wav_path = aiff_path.replace(".aiff", ".wav")
        try:
            subprocess.run(
                ["say", "-o", aiff_path, text],
                check=True, capture_output=True, timeout=10,
            )
            subprocess.run(
                ["afconvert", "-f", "WAVE", "-d", "LEI16", aiff_path, wav_path],
                check=True, capture_output=True,
            )
            data = Path(wav_path).read_bytes()
            return data, text
        finally:
            Path(aiff_path).unlink(missing_ok=True)
            Path(wav_path).unlink(missing_ok=True)
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass

    return None, text


# ---------- D24a/D24b payload builders ----------

def generate_canary_json(
    total_objects: int = 300,
    canaries: dict[int, str] | None = None,
) -> tuple[str, dict[int, str]]:
    """Large JSON array with canaries at head/mid/tail positions (D24a).

    If ``total_objects`` is too small to contain all canary positions, the
    unreachable positions are silently dropped from the returned canary map
    so the postcondition "every returned canary is present in the JSON"
    always holds.

    Canary values use git-commit-ref-style strings ([ref:abc1234]) so a
    router cannot pattern-match the literal word "CANARY".
    """
    if canaries is None:
        from .utils.realistic_prompts import natural_canary
        canaries = {
            10:  f"[ref:{natural_canary('commit')}]",
            150: f"[ref:{natural_canary('commit')}]",
            290: f"[ref:{natural_canary('commit')}]",
        }
    # Drop canary positions that fall outside [0, total_objects).
    canaries = {k: v for k, v in canaries.items() if 0 <= k < total_objects}
    data = []
    for i in range(total_objects):
        obj: dict[str, Any] = {"id": i, "value": f"filler_text_{i}_" + "x" * 30}
        if i in canaries:
            obj["canary"] = canaries[i]
        data.append(obj)
    return json_mod.dumps(data, ensure_ascii=False), canaries


def generate_algebra_text(
    target_tokens: int = 80000,
    variables: dict[int, tuple[str, int]] | None = None,
) -> tuple[str, dict[str, int]]:
    """Long filler text with algebra variable assignments inserted (D24b).

    ``variables`` maps token-position -> (var_name, var_value). Returns
    ``(text, {var_name: value})``.
    """
    if variables is None:
        variables = {
            2000: ("var_X", 14),
            40000: ("var_Y", 5),
            78000: ("var_Z", 2),
        }
    filler_sentence = "The quick brown fox jumps over the lazy dog. "
    # Roughly 10 tokens per sentence.
    filler = filler_sentence * (target_tokens // 10)
    result = filler
    # Insert back-to-front so earlier positions stay stable.
    for token_pos in sorted(variables.keys(), reverse=True):
        var_name, var_value = variables[token_pos]
        char_pos = min(token_pos * 4, len(result))
        insert_text = f"\n{var_name} = {var_value}\n"
        result = result[:char_pos] + insert_text + result[char_pos:]
    var_map = {name: val for _, (name, val) in variables.items()}
    return result, var_map


# ---------- encoding helpers ----------

def to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def to_data_url(data: bytes, media_type: str) -> str:
    return f"data:{media_type};base64,{to_base64(data)}"


# ---------- cache wrappers ----------

def _cache_key(prefix: str, **kw) -> str:
    return f"{prefix}_{repr(sorted(kw.items()))}"


def _cached(key: str, factory):
    """Lazy cache: factory() runs only on miss. Avoids regenerating
    4000x4000 PNGs / PDFs / TTS WAVs on every call.
    """
    if key in _asset_cache:
        return _asset_cache[key]
    value = factory()
    _asset_cache[key] = value
    return value


def get_probe_image(**kw) -> tuple[bytes, str]:
    return _cached(_cache_key("img", **kw), lambda: generate_probe_image(**kw))


def get_nonce_image(text: str) -> bytes:
    return _cached(f"ni_{text}", lambda: generate_nonce_image(text))


def get_probe_pdf(**kw) -> tuple[bytes, str]:
    return _cached(_cache_key("pdf", **kw), lambda: generate_probe_pdf(**kw))


def get_probe_audio(**kw) -> tuple[bytes | None, str]:
    return _cached(_cache_key("aud", **kw), lambda: generate_probe_audio(**kw))


async def aget_probe_audio(**kw) -> tuple[bytes | None, str]:
    """Async variant of :func:`get_probe_audio`.

    When called from an asyncio context, ``generate_probe_audio`` calls
    ``subprocess.run`` which blocks the event loop until TTS finishes.
    This wrapper dispatches the (cached) miss path to the default thread
    executor so other concurrent tasks keep progressing. Cache hits still
    return synchronously -- no executor round-trip overhead.
    """
    key = _cache_key("aud", **kw)
    if key in _asset_cache:
        return _asset_cache[key]
    loop = asyncio.get_running_loop()
    value = await loop.run_in_executor(None, lambda: generate_probe_audio(**kw))
    _asset_cache[key] = value
    return value


# ---------- private helpers ----------

def _random_code(n: int = 6) -> str:
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=n))


def _get_font(size: int):
    from PIL import ImageFont

    for p in _FONT_PATHS:
        try:
            return ImageFont.truetype(p, size)
        except OSError:
            continue
    return ImageFont.load_default()
