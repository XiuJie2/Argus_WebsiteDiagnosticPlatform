"""AI Agent（Strix／argus-agent）服務連線設定——由後台超管在執行期編輯。

引擎已抽離成獨立 HTTP 服務（見本 app 的 CLAUDE.md「引擎已抽離」）。Argus 以
`apps/scans/agent_client.py` 呼叫。連線位址／金鑰原本只能走 `.env`
（`ARGUS_AGENT_SERVICE_*`）；本模型讓它改成後台可寫的執行期設定：

- 單例（pk=1）；後台 `GET/PUT /api/admin/agent-service/` 讀寫。
- `agent_client` 先讀本設定（有填 `base_url` 時以本設定為準），否則退回 `.env`，向後相容。
- `api_key` 以 SECRET_KEY **簽章**存放（沿用 `scans.encrypt_test_auth` 慣例，不同 salt）。
  注意：`Signer` 是防竄改簽章、**不是加密**——明文仍在簽章字串裡，DB-at-rest 機密性
  與既有 `test_auth_*_encrypted` 同級。真正的保護是：金鑰**永不經 API 回傳**，後台只給
  `has_api_key`。若要真正的 at-rest 加密（Fernet），應連同 test_auth 一起升級，另立工項。
"""
from __future__ import annotations

from django.conf import settings
from django.core.signing import Signer
from django.db import models

# 金鑰以 SECRET_KEY 簽章存 DB（與 apps.scans.models 的 test-auth 相同手法，不同 salt）。
_agent_key_signer = Signer(salt="argus-agent-service-key")


def encrypt_secret(value: str) -> str:
    return _agent_key_signer.sign(value) if value else ""


def decrypt_secret(signed: str) -> str:
    if not signed:
        return ""
    try:
        return _agent_key_signer.unsign(signed)
    except Exception:  # noqa: BLE001 — 竄改／換過 SECRET_KEY 時當作無金鑰
        return ""


class AgentServiceConfig(models.Model):
    """AI Agent 服務連線設定（單例 pk=1）。"""

    SINGLETON_ID = 1

    enabled = models.BooleanField(
        default=False,
        help_text="關閉時：若已填服務位址則 agent 階段略過（不呼叫、不計費）。",
    )
    base_url = models.URLField(
        max_length=512,
        blank=True,
        help_text="agent 服務位址，例如 https://strix.example.com（正式請用 HTTPS）。留空＝改用 .env 設定。",
    )
    api_key_encrypted = models.TextField(blank=True, default="")
    timeout_seconds = models.PositiveIntegerField(
        default=1800,
        help_text="同步呼叫逾時（秒）。須大於 agent 服務單次掃描的最長時間。",
    )
    verify_tls = models.BooleanField(
        default=True,
        help_text="正式 HTTPS 一律開啟；僅自簽憑證的內網測試才關閉。",
    )
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )

    class Meta:
        verbose_name = "AI Agent 服務設定"
        verbose_name_plural = "AI Agent 服務設定"

    def __str__(self) -> str:
        return f"AgentServiceConfig(enabled={self.enabled}, url={self.base_url or '-'})"

    def save(self, *args, **kwargs):
        # 強制單例：永遠寫 pk=1。
        self.pk = self.SINGLETON_ID
        super().save(*args, **kwargs)

    @classmethod
    def load(cls) -> "AgentServiceConfig":
        obj, _ = cls.objects.get_or_create(pk=cls.SINGLETON_ID)
        return obj

    # --- api_key：只進不出明文 ---
    @property
    def has_api_key(self) -> bool:
        return bool(self.api_key_encrypted)

    def set_api_key(self, raw: str) -> None:
        self.api_key_encrypted = encrypt_secret(raw or "")

    def get_api_key(self) -> str:
        return decrypt_secret(self.api_key_encrypted)
