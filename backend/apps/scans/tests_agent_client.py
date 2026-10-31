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
    ARGUS_TRANSLATE_FINDINGS=False,  # 契約測試只驗 HTTP 落地；翻譯另有專測
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


class GatherPriorFindingsTests(TestCase):
    def setUp(self):
        from apps.scans.models import Finding
        self.Finding = Finding
        self.user = get_user_model().objects.create_user(
            username="prior-user", password="safe-test-password"
        )

    def _scan(self, status, score=70):
        return ScanJob.objects.create(
            user=self.user, original_url="https://example.com/",
            normalized_url="https://example.com/", origin="https://example.com",
            status=status, overall_score=score, max_pages=50,
        )

    def _fin(self, scan, title, severity, endpoint=""):
        return self.Finding.objects.create(
            scan_job=scan, category="security", severity=severity, title=title,
            evidence_json={"endpoint": endpoint} if endpoint else {},
        )

    def test_union_dedupe_and_cap(self):
        s1 = self._scan(ScanJob.Status.COMPLETED)
        s2 = self._scan(ScanJob.Status.COMPLETED)
        self._fin(s1, "IDOR on password change", "high", "/api/updatePassword")
        # 同一個洞在第二次掃描又出現（措辭略不同、同端點/類型）→ 應去重
        self._fin(s2, "IDOR on the password-change endpoint", "high", "/api/updatePassword")
        self._fin(s2, "Stored XSS in announcement", "medium", "/api/announcement")
        self._fin(s2, "info noise", "info", "")  # info 不納入
        current = self._scan(ScanJob.Status.AGENT_TESTING)

        prior = agent_client.gather_prior_findings(current)
        titles = [p["title"] for p in prior]
        # info 被排除
        assert all(p["severity"] != "info" for p in prior)
        # 兩次的 IDOR 收斂成一筆
        idor = [t for t in titles if "IDOR" in t or "password" in t.lower()]
        assert len(idor) == 1, titles
        # 最嚴重排前面
        assert prior[0]["severity"] == "high"

    def test_no_prior_returns_empty(self):
        current = self._scan(ScanJob.Status.AGENT_TESTING)
        assert agent_client.gather_prior_findings(current) == []


class CarryForwardOpenFindingsTests(TestCase):
    def setUp(self):
        from apps.scans.models import Finding
        self.Finding = Finding
        self.user = get_user_model().objects.create_user(
            username="carry-user", password="safe-test-password"
        )

    def _scan(self, status):
        return ScanJob.objects.create(
            user=self.user, original_url="https://example.com/",
            normalized_url="https://example.com/", origin="https://example.com",
            status=status, overall_score=70, max_pages=50,
        )

    def _fin(self, scan, title, sev, rule_id, endpoint=""):
        return self.Finding.objects.create(
            scan_job=scan, category="security", severity=sev, title=title, rule_id=rule_id,
            evidence_json={"endpoint": endpoint} if endpoint else {},
        )

    def test_carries_nondeterministic_not_in_current_skips_deterministic(self):
        from apps.scans.cumulative import carry_forward_open_findings
        prev = self._scan(ScanJob.Status.COMPLETED)
        self._fin(prev, "IDOR on /api/updatePassword", "high", "strix:vuln-0005", "/api/updatePassword")
        self._fin(prev, "缺少 HSTS", "medium", "SECURITY_HSTS_X")  # 確定性 → 不帶
        cur = self._scan(ScanJob.Status.AGENT_TESTING)
        carried = carry_forward_open_findings(cur, current_findings=[])
        titles = [c["title"] for c in carried]
        assert any("IDOR" in t for t in titles), titles
        assert not any("HSTS" in t for t in titles), titles
        # 真的落了一筆 carried_over 的 Finding 到本次掃描
        row = cur.findings.filter(evidence_source="carried_over").first()
        assert row is not None and row.evidence_json.get("carried_over") is True

    def test_skips_if_reconfirmed_this_scan(self):
        from apps.scans.cumulative import carry_forward_open_findings
        from apps.scans.finding_identity import finding_identity
        prev = self._scan(ScanJob.Status.COMPLETED)
        self._fin(prev, "Stored XSS in announcement", "high", "strix:vuln-0004", "/api/announcement")
        cur = self._scan(ScanJob.Status.AGENT_TESTING)
        current = [{"category": "security", "title": "Stored XSS in announcement",
                    "description": "", "owasp_category": "", "cwe_id": "",
                    "evidence_json": {"endpoint": "/api/announcement"}, "rule_id": "strix:vuln-0004"}]
        carried = carry_forward_open_findings(cur, current_findings=current)
        assert carried == []  # 本次已重新確認 → 不重複帶

    def test_no_prior_empty(self):
        from apps.scans.cumulative import carry_forward_open_findings
        cur = self._scan(ScanJob.Status.AGENT_TESTING)
        assert carry_forward_open_findings(cur, current_findings=[]) == []

    def _complete(self, scan):
        scan.status = ScanJob.Status.COMPLETED
        scan.save(update_fields=["status"])
        return scan

    _SURFACE = [
        ("IDOR on /api/a", "strix:vuln-0001", "/api/a"),
        ("XSS on /api/b", "strix:vuln-0002", "/api/b"),
        ("CSRF on /api/c", "strix:vuln-0003", "/api/c"),
        ("SQLi on /api/d", "strix:vuln-0004", "/api/d"),
        ("IDOR on /api/updatePassword", "strix:vuln-0005", "/api/updatePassword"),
    ]

    def _current_for(self, items):
        """由 (title, rule_id, endpoint) 造出本次重新確認的 current_findings dict。
        端點放在 evidence_json（finding_identity 由此取資源，與落地列一致）。"""
        return [{"category": "security", "title": t, "description": "", "owasp_category": "",
                 "cwe_id": "", "evidence_json": {"endpoint": ep}, "rule_id": rid}
                for (t, rid, ep) in items]

    def _seed_surface(self):
        prev = self._scan(ScanJob.Status.COMPLETED)
        for (t, rid, ep) in self._SURFACE:
            self._fin(prev, t, "high", rid, ep)
        return prev

    def test_reverify_resolves_only_after_thorough_misses(self):
        """agent 認真重測（重新確認多數發現）卻連續兩次沒打到某一項 → 判定修復、停止帶入。"""
        from apps.scans.cumulative import carry_forward_open_findings
        from apps.scans.models import AgentFindingState
        self._seed_surface()
        # 每次都重新確認前 4 項（thorough），唯獨漏掉最後一項（updatePassword）
        confirmed = self._current_for(self._SURFACE[:4])
        for _ in range(2):
            cur = self._scan(ScanJob.Status.AGENT_TESTING)
            carry_forward_open_findings(cur, current_findings=confirmed, agent_ran_ok=True)
            self._complete(cur)
        resolved = AgentFindingState.objects.filter(user=self.user, resolved=True)
        assert resolved.count() == 1, list(resolved.values_list("identity", "miss_streak"))
        assert "updatepassword" in resolved.first().identity

    def test_deterministic_reconfirm_does_not_count_as_agent_verification(self):
        """只有確定性層重新確認、agent 空跑 → 不算 thorough，agent-only 的洞不被消解。"""
        from apps.scans.cumulative import carry_forward_open_findings
        from apps.scans.models import AgentFindingState
        self._seed_surface()
        # 本次「重新確認」前 4 項，但來源是確定性層（rule_id 非 strix/agent），agent 本身空跑。
        det = [{"category": "security", "title": t, "description": "", "owasp_category": "",
                "cwe_id": "", "evidence_json": {"endpoint": ep}, "rule_id": "SECURITY_DET_X"}
               for (t, _rid, ep) in self._SURFACE[:4]]
        for _ in range(3):
            cur = self._scan(ScanJob.Status.AGENT_TESTING)
            carry_forward_open_findings(cur, current_findings=det, agent_ran_ok=True)
            self._complete(cur)
        # 確定性重新確認不應讓 thorough 成立 → updatePassword（agent-only）不被消解
        assert AgentFindingState.objects.filter(user=self.user, resolved=True).count() == 0
        st = AgentFindingState.objects.get(user=self.user, identity__contains="updatepassword")
        assert st.resolved is False and st.miss_streak == 0, (st.resolved, st.miss_streak)

    def test_weak_agent_run_does_not_resolve(self):
        """agent 完成卻幾乎沒重新確認（空跑）→ 不算驗證，全部照帶、不消解。"""
        from apps.scans.cumulative import carry_forward_open_findings
        from apps.scans.models import AgentFindingState
        self._seed_surface()
        for _ in range(3):
            cur = self._scan(ScanJob.Status.AGENT_TESTING)
            # 只重新確認 1 項（低於 thorough 門檻）→ 其餘不應扣 miss
            carried = carry_forward_open_findings(
                cur, current_findings=self._current_for(self._SURFACE[:1]), agent_ran_ok=True)
            assert len(carried) == 4, len(carried)  # 另外 4 項照帶
            self._complete(cur)
        assert AgentFindingState.objects.filter(user=self.user, resolved=True).count() == 0
        assert set(AgentFindingState.objects.filter(user=self.user)
                   .values_list("miss_streak", flat=True)) <= {0}

    def test_failed_agent_run_does_not_count_as_verification(self):
        """agent 失敗/被限流（agent_ran_ok=False）→ 不扣 miss，持續帶入（不誤判已修復）。"""
        from apps.scans.cumulative import carry_forward_open_findings
        from apps.scans.models import AgentFindingState
        prev = self._scan(ScanJob.Status.COMPLETED)
        self._fin(prev, "IDOR on /api/updatePassword", "high", "strix:vuln-0005", "/api/updatePassword")
        for _ in range(3):
            cur = self._scan(ScanJob.Status.AGENT_TESTING)
            carried = carry_forward_open_findings(cur, current_findings=[], agent_ran_ok=False)
            assert len(carried) == 1, carried  # 每次都照帶
            self._complete(cur)
        st = AgentFindingState.objects.get(user=self.user, origin="https://example.com")
        assert st.miss_streak == 0 and st.resolved is False

    def test_reconfirm_resets_miss_streak(self):
        """thorough 掃描漏掉 → miss=1；下次重新打到 → miss 歸零，不會被誤消解。"""
        from apps.scans.cumulative import carry_forward_open_findings
        from apps.scans.models import AgentFindingState
        self._seed_surface()
        # 第 1 次 thorough 掃描確認前 4 項、漏掉 updatePassword → 它 miss=1
        s1 = self._scan(ScanJob.Status.AGENT_TESTING)
        carry_forward_open_findings(s1, current_findings=self._current_for(self._SURFACE[:4]),
                                    agent_ran_ok=True)
        self._complete(s1)
        st = AgentFindingState.objects.get(user=self.user, identity__contains="updatepassword")
        assert st.miss_streak == 1, st.miss_streak
        # 第 2 次重新打到全部 5 項 → updatePassword miss 歸零
        s2 = self._scan(ScanJob.Status.AGENT_TESTING)
        carried = carry_forward_open_findings(s2, current_findings=self._current_for(self._SURFACE),
                                              agent_ran_ok=True)
        assert carried == [], carried
        st.refresh_from_db()
        assert st.miss_streak == 0 and st.resolved is False

    def test_carried_keeps_full_description_and_remediation(self):
        """帶入的發現要有完整原始說明（不截斷）與 remediation（怎麼修不為空）。"""
        from apps.scans.cumulative import carry_forward_open_findings
        prev = self._scan(ScanJob.Status.COMPLETED)
        long_desc = "A" * 450  # > 舊的 300 截斷上限
        self.Finding.objects.create(
            scan_job=prev, category="security", severity="high",
            title="IDOR on /api/updatePassword", rule_id="strix:vuln-0005",
            description=long_desc, remediation="綁定資源擁有者後再授權存取。",
            evidence_json={"endpoint": "/api/updatePassword"},
        )
        cur = self._scan(ScanJob.Status.AGENT_TESTING)
        carried = carry_forward_open_findings(cur, current_findings=[], agent_ran_ok=False)
        assert len(carried) == 1, carried
        row = cur.findings.filter(evidence_source="carried_over").first()
        assert row is not None
        assert len(row.description) == 450, len(row.description)  # 未被截斷
        assert row.remediation == "綁定資源擁有者後再授權存取。", row.remediation

    def test_carried_prefers_original_over_prior_carried_source(self):
        """內容來源優先取原始列：即使前次也留了一筆 carried（無 remediation）。"""
        from apps.scans.cumulative import carry_forward_open_findings
        # 原始列（有 remediation）在較早的掃描
        s_orig = self._scan(ScanJob.Status.COMPLETED)
        self.Finding.objects.create(
            scan_job=s_orig, category="security", severity="high",
            title="IDOR on /api/updatePassword", rule_id="strix:vuln-0005",
            description="原始完整說明", remediation="正確的修法",
            evidence_json={"endpoint": "/api/updatePassword"},
        )
        # 前次 carried 列（無 remediation）在較晚的掃描
        s_carry = self._scan(ScanJob.Status.COMPLETED)
        self.Finding.objects.create(
            scan_job=s_carry, category="security", severity="high",
            title="IDOR on /api/updatePassword", rule_id="strix:vuln-0005",
            description="原始完整說明", remediation="", evidence_source="carried_over",
            evidence_json={"endpoint": "/api/updatePassword", "carried_over": True},
        )
        cur = self._scan(ScanJob.Status.AGENT_TESTING)
        carried = carry_forward_open_findings(cur, current_findings=[], agent_ran_ok=False)
        row = cur.findings.filter(evidence_source="carried_over").first()
        assert row is not None and row.remediation == "正確的修法", row.remediation
