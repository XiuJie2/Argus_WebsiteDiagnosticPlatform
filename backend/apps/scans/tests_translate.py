"""translate.py：英文發現→繁中翻譯 + 快取 + fail-open。"""
from __future__ import annotations

import json

from django.test import TestCase, override_settings


class _StubResp:
    def __init__(self, content, model="stub-model"):
        self.content = content
        self.model = model


class _StubChain:
    def __init__(self, content):
        self._content = content
        self.calls = 0

    def chat_text(self, prompt, temperature=0.2, max_tokens=2048, **kw):
        self.calls += 1
        return _StubResp(self._content)


class _RaisingChain:
    def chat_text(self, *a, **k):
        raise RuntimeError("provider down")


_EN = {
    "title": "Account passwords stored in plaintext and returned by the login API",
    "description": "User and administrator passwords are stored in plaintext and echoed back.",
    "remediation": "Store passwords as salted adaptive hashes (Argon2id, bcrypt).",
}
_ZH_JSON = json.dumps({
    "title": "帳號密碼以明文儲存並由登入 API 回傳",
    "description": "使用者與管理員密碼以明文儲存並原樣回傳。",
    "remediation": "改用加鹽的自適應雜湊（Argon2id、bcrypt）儲存密碼。",
}, ensure_ascii=False)


class LooksEnglishTests(TestCase):
    def test_detects_english_and_chinese(self):
        from apps.scans.translate import looks_english
        assert looks_english(_EN["title"]) is True
        assert looks_english("帳號密碼以明文儲存並由登入 API 回傳") is False
        assert looks_english("") is False


@override_settings(ARGUS_TRANSLATE_FINDINGS=True, ARGUS_TRANSLATE_TARGET_LANG="zh-Hant")
class TranslateFieldsTests(TestCase):
    def test_translates_and_caches(self):
        from apps.scans.translate import translate_finding_fields
        from apps.scans.models import FindingTranslation
        chain = _StubChain(_ZH_JSON)
        out = translate_finding_fields(dict(_EN), chain=chain)
        assert out["title"].startswith("帳號密碼"), out["title"]
        assert "Argon2id" in out["remediation"]  # 技術符號保留
        assert FindingTranslation.objects.count() == 1
        # 第二次：命中快取，不再呼叫 chain
        chain2 = _StubChain(_ZH_JSON)
        out2 = translate_finding_fields(dict(_EN), chain=chain2)
        assert out2["title"] == out["title"]
        assert chain2.calls == 0, "應命中快取，不應再呼叫 LLM"

    def test_fail_open_keeps_english(self):
        from apps.scans.translate import translate_finding_fields
        out = translate_finding_fields(dict(_EN), chain=_RaisingChain())
        assert out == {k: _EN[k] for k in ("title", "description", "remediation")}

    def test_skips_chinese_input(self):
        from apps.scans.translate import translate_finding_fields
        zh_in = {"title": "缺少 HSTS 標頭", "description": "網站未設定 HSTS。", "remediation": "加上 HSTS 標頭。"}
        chain = _StubChain(_ZH_JSON)
        out = translate_finding_fields(dict(zh_in), chain=chain)
        assert out == zh_in and chain.calls == 0

    @override_settings(ARGUS_TRANSLATE_FINDINGS=False)
    def test_disabled_returns_english(self):
        from apps.scans.translate import translate_finding_fields
        chain = _StubChain(_ZH_JSON)
        out = translate_finding_fields(dict(_EN), chain=chain)
        assert out["title"] == _EN["title"] and chain.calls == 0


_EV_EN = (
    "Administrator listing returns a cleartext password to a role:User session:\n\n"
    "```http\nGET /api/admin/selectPage HTTP/1.1\nHost: x.test\n```\n"
    "```json\n{\"password\":\"JunNewPass123!\"}\n```"
)
_EV_ZH = (
    "管理員列表會向 role:User 會話回傳明文密碼：\n\n"
    "```http\nGET /api/admin/selectPage HTTP/1.1\nHost: x.test\n```\n"
    "```json\n{\"password\":\"JunNewPass123!\"}\n```"
)


@override_settings(ARGUS_TRANSLATE_FINDINGS=True, ARGUS_TRANSLATE_TARGET_LANG="zh-Hant")
class TranslateEvidenceTests(TestCase):
    def test_translates_prose_keeps_code_and_caches(self):
        from apps.scans.translate import translate_evidence
        from apps.scans.models import FindingTranslation
        chain = _StubChain(_EV_ZH)
        out = translate_evidence(_EV_EN, chain=chain)
        assert out.startswith("管理員列表")
        assert "JunNewPass123!" in out and "GET /api/admin/selectPage" in out
        assert FindingTranslation.objects.count() == 1
        chain2 = _StubChain(_EV_ZH)
        assert translate_evidence(_EV_EN, chain=chain2) == out and chain2.calls == 0

    def test_fail_open_and_truncation_guard(self):
        from apps.scans.translate import translate_evidence
        # 失敗 → 原文
        assert translate_evidence(_EV_EN, chain=_RaisingChain()) == _EV_EN
        # 疑似截斷（回應過短）→ 原文
        assert translate_evidence(_EV_EN, chain=_StubChain("太短")) == _EV_EN

    def test_skips_long_or_empty(self):
        from apps.scans.translate import translate_evidence
        chain = _StubChain(_EV_ZH)
        assert translate_evidence("", chain=chain) == ""
        big = "A" * 9000
        assert translate_evidence(big, chain=chain) == big
        assert chain.calls == 0
