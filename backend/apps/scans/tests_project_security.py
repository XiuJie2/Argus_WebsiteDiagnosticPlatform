"""資安分析頁 GET /api/projects/<id>/security/：只收資安問題，沿用問題分析的合併與比較。"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from apps.scans.models import Finding, ScanJob

User = get_user_model()

OBSERVATORY = {"tool": "Mozilla HTTP Observatory 規則", "url": "https://example.com/", "score": 55,
               "grade": "C", "bonus_applied": False, "tests": []}


class ProjectSecurityTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="sec-page", password="safe-test-password")
        self.scan = ScanJob.objects.create(
            user=self.user, original_url="https://example.com/",
            normalized_url="https://example.com/", origin="https://example.com",
            status=ScanJob.Status.COMPLETED, completed_at=timezone.now(),
            category_scores={"security": 61, "seo": 90},
            coverage={
                "checks": {"nuclei": {"status": "failed", "category": "security", "keys": []}},
                "categories": {"security": "partial"},
            },
            site_profile={
                "observatory": OBSERVATORY,
                "infrastructure": {"edge": {"provider": "Cloudflare"}},
                "strengths": [
                    {"key": "https", "category": "security", "title": "全站使用 HTTPS"},
                    {"key": "robots", "category": "seo", "title": "有 robots.txt"},
                ],
            },
        )
        for category, rule_id, title, severity in (
            ("security", "SECURITY_CSP_X", "缺少 CSP", "low"),
            ("security", "header-hsts-missing", "缺少 HSTS", "medium"),
            ("security", "js-lib-known-vuln", "前端函式庫有已知漏洞", "medium"),
            ("seo", "SEO_H1_X", "H1 數量不正確", "low"),
        ):
            Finding.objects.create(
                scan_job=self.scan, category=category, severity=severity, title=title,
                description="d", remediation="r", rule_id=rule_id, ai_handoff_prompt="p",
            )
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def _get(self, user=None):
        if user:
            self.client.force_authenticate(user=user)
        return self.client.get(f"/api/projects/{self.scan.project_id}/security/")

    def test_security_only_with_kinds_root_causes_and_strengths(self):
        data = self._get().json()

        self.assertTrue(data["checked"])
        self.assertEqual((data["score"], data["coverage"]), (61, "partial"))
        self.assertEqual(data["incomplete_checks"], ["Nuclei 主動弱點掃描"])
        self.assertEqual(data["observatory"]["grade"], "C")
        self.assertEqual(data["edge"]["provider"], "Cloudflare")
        self.assertEqual(
            sorted(i["title"] for i in data["issues"]),
            ["前端函式庫有已知漏洞", "缺少 CSP", "缺少 HSTS"],
        )
        counts = {k["kind"]: k["count"] for k in data["kinds"]}
        self.assertEqual(counts, {"config": 2, "exposure": 0, "suspected": 1, "verified": 0})
        self.assertEqual([c["id"] for c in data["root_causes"]], ["server-headers"])
        self.assertEqual([s["title"] for s in data["strengths"]], ["全站使用 HTTPS"])

    def test_scan_without_security_category(self):
        self.scan.categories = ["seo"]
        self.scan.save(update_fields=["categories"])
        data = self._get().json()
        self.assertFalse(data["checked"])
        self.assertEqual(data["issues"], [])

    def test_no_completed_scan_and_other_users(self):
        other = User.objects.create_user(username="sec-other", password="safe-test-password")
        self.assertEqual(self._get(user=other).status_code, 404)
        self.scan.status = ScanJob.Status.FAILED
        self.scan.save(update_fields=["status"])
        self.assertEqual(self._get(user=self.user).json(), {"scan": None})
