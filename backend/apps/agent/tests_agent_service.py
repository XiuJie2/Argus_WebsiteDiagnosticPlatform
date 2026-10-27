"""AgentServiceConfig（後台可寫的 AI Agent 服務設定）與 agent_client 解析優先序測試。"""
from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from apps.agent.models import AgentServiceConfig, decrypt_secret, encrypt_secret
from apps.scans.agent_client import _resolve_service

User = get_user_model()


class AgentServiceConfigModelTests(TestCase):
    def test_singleton_load_and_save_pk(self):
        a = AgentServiceConfig.load()
        a.base_url = "https://strix.example.com"
        a.save()
        b = AgentServiceConfig.load()
        self.assertEqual(a.pk, AgentServiceConfig.SINGLETON_ID)
        self.assertEqual(b.base_url, "https://strix.example.com")
        self.assertEqual(AgentServiceConfig.objects.count(), 1)

    def test_api_key_sign_roundtrip(self):
        cfg = AgentServiceConfig.load()
        self.assertFalse(cfg.has_api_key)
        cfg.set_api_key("super-secret-token")
        cfg.save()
        # Signer 是簽章（防竄改）非加密——明文仍在簽章字串裡（與 scans.test_auth 相同慣例）。
        # 真正的保護是：金鑰永不經 API 回傳（見 endpoint 測試）。此處只驗 roundtrip 與簽章附加。
        self.assertTrue(cfg.has_api_key)
        self.assertEqual(cfg.get_api_key(), "super-secret-token")
        self.assertNotEqual(cfg.api_key_encrypted, "super-secret-token")  # 有附簽章
        # 竄改簽章 → 視為無效（回空字串）
        cfg.api_key_encrypted = cfg.api_key_encrypted + "tampered"
        self.assertEqual(cfg.get_api_key(), "")

    def test_decrypt_bad_value_returns_empty(self):
        self.assertEqual(decrypt_secret("not-a-valid-signed-value"), "")
        self.assertEqual(decrypt_secret(""), "")
        self.assertEqual(encrypt_secret(""), "")


@override_settings(
    ARGUS_AGENT_SERVICE_URL="",
    ARGUS_AGENT_SERVICE_KEY="",
    ARGUS_AGENT_SERVICE_TIMEOUT=1800,
)
class ResolveServiceTests(TestCase):
    def test_no_config_no_env_returns_none(self):
        self.assertIsNone(_resolve_service())

    def test_db_config_enabled_wins(self):
        cfg = AgentServiceConfig.load()
        cfg.enabled = True
        cfg.base_url = "https://strix.example.com/"
        cfg.set_api_key("k")
        cfg.timeout_seconds = 900
        cfg.verify_tls = True
        cfg.save()
        base, key, timeout, verify = _resolve_service()
        self.assertEqual(base, "https://strix.example.com")  # 去尾斜線
        self.assertEqual(key, "k")
        self.assertEqual(timeout, 900)
        self.assertTrue(verify)

    def test_db_config_disabled_with_url_returns_none(self):
        cfg = AgentServiceConfig.load()
        cfg.enabled = False
        cfg.base_url = "https://strix.example.com"
        cfg.save()
        self.assertIsNone(_resolve_service())

    @override_settings(ARGUS_AGENT_SERVICE_URL="http://env-agent:8099", ARGUS_AGENT_SERVICE_KEY="envkey")
    def test_blank_db_url_falls_back_to_env(self):
        AgentServiceConfig.load()  # 建立但不填 base_url
        base, key, timeout, verify = _resolve_service()
        self.assertEqual(base, "http://env-agent:8099")
        self.assertEqual(key, "envkey")


class AgentServiceAdminEndpointTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.super = User.objects.create_user(
            username="root", email="root@example.com", password="x", is_staff=True, is_superuser=True
        )
        self.staff = User.objects.create_user(
            username="staff", email="staff@example.com", password="x", is_staff=True
        )
        self.url = reverse("admin-agent-service")

    def test_requires_superuser(self):
        self.assertEqual(self.client.get(self.url).status_code, 401)
        self.client.force_authenticate(self.staff)
        self.assertEqual(self.client.get(self.url).status_code, 403)

    def test_get_and_put_roundtrip_masks_key(self):
        self.client.force_authenticate(self.super)
        # 初始
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.data["has_api_key"])
        # 寫入含金鑰
        r = self.client.put(self.url, {
            "enabled": True,
            "base_url": "https://strix.example.com",
            "api_key": "s3cr3t",
            "timeout_seconds": 1200,
            "verify_tls": True,
        }, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.data["has_api_key"])
        self.assertNotIn("api_key", r.data)  # 金鑰不回傳
        self.assertNotIn("s3cr3t", str(r.data))
        # DB 真有存到金鑰（密文）
        cfg = AgentServiceConfig.load()
        self.assertEqual(cfg.get_api_key(), "s3cr3t")

    def test_blank_api_key_keeps_existing(self):
        self.client.force_authenticate(self.super)
        self.client.put(self.url, {"base_url": "https://a.example.com", "api_key": "keep"},
                        format="json")
        # 再次 PUT 不帶 api_key → 保留
        self.client.put(self.url, {"base_url": "https://a.example.com", "timeout_seconds": 60},
                        format="json")
        self.assertEqual(AgentServiceConfig.load().get_api_key(), "keep")

    def test_clear_api_key(self):
        self.client.force_authenticate(self.super)
        self.client.put(self.url, {"base_url": "https://a.example.com", "api_key": "x"}, format="json")
        self.client.put(self.url, {"base_url": "https://a.example.com", "clear_api_key": True},
                        format="json")
        self.assertFalse(AgentServiceConfig.load().has_api_key)

    def test_put_writes_audit_without_secret(self):
        from apps.admin_api.models import AdminAuditLog

        self.client.force_authenticate(self.super)
        self.client.put(self.url, {"base_url": "https://a.example.com", "api_key": "topsecret"},
                        format="json")
        log = AdminAuditLog.objects.filter(action=AdminAuditLog.Action.AGENT_CONFIG).first()
        self.assertIsNotNone(log)
        self.assertNotIn("topsecret", str(log.payload))
