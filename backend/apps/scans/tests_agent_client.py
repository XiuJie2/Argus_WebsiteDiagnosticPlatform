"""agent_client（統一 HTTP 契約）測試：正規化與落地 backend-agnostic。

驗證不同引擎（argus-agent／Strix wrapper）回傳的 severity／OWASP／CWE／CVSS 格式差異，
都能被正確正規化並落地成一致的 Finding。
"""
from __future__ import annotations

from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from apps.scans import agent_client
from apps.scans.models import Finding, ScanJob


class NormalizeHelperTests(TestCase):
    def test_severity_synonyms(self):
        n = agent_client._normalize_severity
        self.assertEqual(n("CRITICAL"), "critical")
        self.assertEqual(n("Informational"), "info")
        self.assertEqual(n("moderate"), "medium")
        self.assertEqual(n("error"), "high")
        self.assertEqual(n(""), "low")  # 未知退回 low
        self.assertEqual(n("不認得"), "low")

    def test_owasp_normalization(self):
        n = agent_client._normalize_owasp
        self.assertEqual(n("A1"), "A01")
        self.assertEqual(n("A01"), "A01")
        self.assertEqual(n("A01:2021"), "A01")
        self.assertEqual(n("A01:2021-Broken Access Control"), "A01")
        self.assertEqual(n("A10"), "A10")
        self.assertEqual(n("A11"), "")  # 超出範圍
        self.assertEqual(n(""), "")

    def test_cwe_normalization(self):
        n = agent_client._normalize_cwe
        self.assertEqual(n("CWE-862"), "CWE-862")
        self.assertEqual(n("862"), "CWE-862")
        self.assertEqual(n("CWE 862"), "CWE-862")
        self.assertEqual(n(""), "")

    def test_priority_from_cvss(self):
        p = agent_client._priority_from_item
        self.assertEqual(p({"priority_score": 77}), 77.0)  # 顯式優先
        self.assertEqual(p({"cvss": 8.6}), 86.0)  # CVSS×10
        self.assertEqual(p({"cvss_score": 11}), 100.0)  # 夾在 0–10
        self.assertIsNone(p({}))


@override_settings(
    ARGUS_AGENT_SERVICE_URL="https://agent.example.test",
    ARGUS_AGENT_SERVICE_KEY="",
    ARGUS_AGENT_SERVICE_TIMEOUT=10,
)
class RunAgentViaServiceTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="agent-client-user", password="safe-test-password"
        )
        self.scan = ScanJob.objects.create(
            user=self.user,
            original_url="https://example.com/",
            normalized_url="https://example.com/",
            origin="https://example.com",
            status=ScanJob.Status.AGENT_TESTING,
            max_pages=50,
        )

    def _post(self, payload):
        resp = mock.Mock()
        resp.raise_for_status.return_value = None
        resp.json.return_value = payload
        return resp

    def test_no_url_skips(self):
        with override_settings(ARGUS_AGENT_SERVICE_URL=""):
            self.assertIsNone(
                agent_client.run_agent_via_service(
                    self.scan, run_deep=True, run_ux=False
                )
            )

    def test_strix_style_response_lands(self):
        # Strix 風格：vulnerabilities 別名、CVSS、A01:2021、CWE 無前綴、severity 同義詞、無 category
        body = {
            "status": "completed",
            "steps": 42,
            "total_tokens": 1000,
            "final_summary": "done",
            "vulnerabilities": [
                {
                    "title": "IDOR on /api/users",
                    "description": "可讀他人資料",
                    "severity": "High",
                    "owasp": "A01:2021-Broken Access Control",
                    "cwe": "639",
                    "cvss": 8.6,
                    "url": "https://example.com/api/users",
                },
                {
                    "category": "ux",
                    "title": "按鈕無回饋",
                    "description": "點了沒反應",
                    "severity": "moderate",
                },
            ],
        }
        with mock.patch(
            "apps.scans.agent_client.requests.post", return_value=self._post(body)
        ) as post:
            result = agent_client.run_agent_via_service(
                self.scan, run_deep=True, run_ux=True
            )

        # 契約版本與 mode=both 有送出
        sent = post.call_args.kwargs["json"]
        self.assertEqual(sent["mode"], "both")
        self.assertEqual(sent["contract_version"], agent_client.CONTRACT_VERSION)

        self.assertIsNotNone(result)
        self.assertEqual(result.final_summary, "done")
        self.assertEqual(len(result.security_findings), 1)
        self.assertEqual(len(result.issues), 1)

        sec = Finding.objects.get(scan_job=self.scan, category="security")
        self.assertEqual(sec.severity, "high")
        self.assertEqual(sec.owasp_category, "A01")
        self.assertEqual(sec.cwe_id, "CWE-639")
        self.assertEqual(sec.priority_score, 86.0)  # CVSS 8.6 × 10
        self.assertIsNone(sec.page)  # 這次掃描沒有對應 Page，掛空

    def test_missing_category_defaults_security(self):
        body = {"findings": [{"title": "X", "description": "d", "severity": "low"}]}
        with mock.patch("apps.scans.agent_client.requests.post", return_value=self._post(body)):
            result = agent_client.run_agent_via_service(
                self.scan, run_deep=True, run_ux=False
            )
        self.assertEqual(len(result.security_findings), 1)
        self.assertEqual(Finding.objects.filter(category="security").count(), 1)
