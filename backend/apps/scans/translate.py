"""把 AI/Agent（Strix）英文發現轉成精簡清晰的繁體中文。

為什麼：Strix 以英文回報 title/description/remediation，但 argus 面向繁中使用者。
在發現落地（_persist_finding）時翻譯，報告與前端就都是中文；evidence（原始 HTTP/程式碼
佐證）維持原文不動，避免破壞可驗證性。

設計：
- 只翻英文內容（已是中文的確定性發現會被語言偵測跳過，不浪費 token）。
- 以來源文字 sha256 快取（FindingTranslation）：同一筆跨掃描重複、或被 carry-forward
  帶入時只翻一次。
- fail-open：LLM 不可用／回傳無法解析時，原樣保留英文，絕不讓翻譯失敗影響掃描或掉發現。
- 重用既有 ProviderChain（MiniMax→GLM→Gemini），不另接模型。
"""
from __future__ import annotations

import hashlib
import json
import logging
import re

from django.conf import settings

logger = logging.getLogger(__name__)

_CJK = re.compile(r"[一-鿿]")
_LATIN = re.compile(r"[A-Za-z]")
_FIELDS = ("title", "description", "remediation")


def looks_english(text: str) -> bool:
    """粗略判斷字串是否以英文為主（值得翻譯）。中文佔比高就跳過。"""
    if not text:
        return False
    latin = len(_LATIN.findall(text))
    cjk = len(_CJK.findall(text))
    return latin >= 12 and cjk < max(1, latin) * 0.15


def _source_hash(fields: dict, target: str) -> str:
    raw = "\u0001".join(str(fields.get(k) or "") for k in _FIELDS) + f"\u0002{target}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _build_prompt(fields: dict, target_label: str) -> str:
    payload = {k: (fields.get(k) or "") for k in _FIELDS}
    return (
        f"你是資安報告的專業譯者。把下列網站弱點發現的英文欄位翻成{target_label}，"
        "服務對象是非資安背景的一般網站管理者。要求：\n"
        "1. 精簡、清晰、口語但專業；能短則短，不要逐字直譯、不要贅字。\n"
        "2. 保留技術符號原文不翻：端點路徑、HTTP 方法與標頭名、參數名、程式碼、"
        "CWE/OWASP 代號、產品名。這些包在反引號或括號裡時原樣保留。\n"
        "3. 維持原本的 Markdown 粗體/清單等格式。\n"
        "4. remediation 若是編號步驟，維持編號步驟。\n"
        "5. 只輸出一個 JSON 物件，鍵為 title/description/remediation，值為翻譯後字串；"
        "不要加任何說明或程式碼圍欄。\n\n"
        f"英文欄位（JSON）：\n{json.dumps(payload, ensure_ascii=False, indent=1)}"
    )


def _parse_json(content: str) -> dict | None:
    if not content:
        return None
    txt = content.strip()
    # 去掉可能的 ```json ... ``` 圍欄
    if txt.startswith("```"):
        txt = re.sub(r"^```[a-zA-Z]*\n?", "", txt)
        txt = re.sub(r"\n?```$", "", txt).strip()
    try:
        data = json.loads(txt)
    except Exception:  # noqa: BLE001
        start, end = txt.find("{"), txt.rfind("}")
        if start == -1 or end <= start:
            return None
        try:
            data = json.loads(txt[start:end + 1])
        except Exception:  # noqa: BLE001
            return None
    return data if isinstance(data, dict) else None


def translate_finding_fields(fields: dict, *, chain=None) -> dict:
    """翻譯 title/description/remediation；回傳含翻譯後三欄的 dict。

    任何一步失敗或關閉時，對應欄位原樣回傳英文（fail-open）。evidence 等其他欄位不處理。
    """
    out = {k: (fields.get(k) or "") for k in _FIELDS}
    if not getattr(settings, "ARGUS_TRANSLATE_FINDINGS", True):
        return out
    # 值得翻的前提：至少有一個欄位看起來是英文
    if not any(looks_english(out[k]) for k in _FIELDS):
        return out

    target = getattr(settings, "ARGUS_TRANSLATE_TARGET_LANG", "zh-Hant") or "zh-Hant"
    target_label = "繁體中文（台灣用語）" if target.lower().startswith("zh") else target

    from apps.scans.models import FindingTranslation

    key = _source_hash(out, target)
    cached = FindingTranslation.objects.filter(source_hash=key, target_lang=target).first()
    if cached and isinstance(cached.payload, dict):
        return {k: (cached.payload.get(k) or out[k]) for k in _FIELDS}

    try:
        from apps.agent.providers import build_default_chain

        chain = chain or build_default_chain()
        resp = chain.chat_text(_build_prompt(out, target_label), temperature=0.1, max_tokens=1600)
        data = _parse_json(resp.content)
    except Exception as exc:  # noqa: BLE001 — 翻譯失敗保留英文
        logger.warning("翻譯發現失敗，保留英文：%s", exc)
        return out

    if not data:
        return out

    translated = {k: (str(data.get(k)).strip() if data.get(k) else out[k]) for k in _FIELDS}
    try:
        FindingTranslation.objects.update_or_create(
            source_hash=key, target_lang=target,
            defaults={"payload": translated, "model": getattr(resp, "model", "")[:128]},
        )
    except Exception:  # noqa: BLE001 — 快取寫入失敗不影響回傳
        logger.debug("翻譯快取寫入失敗 hash=%s", key[:12])
    return translated
