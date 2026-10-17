"""跨層資安發現去重測試（security/cross_layer.py）。"""

from __future__ import annotations

from django.test import SimpleTestCase

from apps.agent.findings import agent_security_rule_id
from apps.scans.security.cross_layer import consolidate_cross_layer


def _exposure(endpoint: str, rule_id: str = "exposure-file-apidoc") -> dict:
    return {
        "category": "security",
        "severity": "high",
        "rule_id": rule_id,
        "title": "敏感檔案外洩：API 文件",
        "description": f"發現可公開存取的 API 文件：https://site.example.test{endpoint}。",
        "evidence_source": "exposure_probe",
        "impact_area": "information_exposure",
        "evidence_json": {"endpoint": endpoint},
    }


def _agent(endpoint: str, title: str = "OpenAPI 規格未授權可讀導致後端結構洩漏") -> dict:
    url = f"https://site.example.test{endpoint}"
    return {
        "category": "security",
        "severity": "high",
        "rule_id": agent_security_rule_id(title, "openapi 規格匿名可讀", url),
        "title": title,
        "description": "AI Agent 觀察到規格匿名可讀",
        "evidence_source": "hermes_agent",
        "evidence_json": {"source": "hermes_agent", "observed_endpoint": endpoint},
    }


class ConsolidateCrossLayerTests(SimpleTestCase):
    def test_same_endpoint_drops_agent_keeps_deterministic(self):
        det = _exposure("/svc/v3/api-docs")
        agent = _agent("/svc/v3/api-docs")
        kept, dropped = consolidate_cross_layer([det, agent])
        self.assertIn(det, kept)
        self.assertNotIn(agent, kept)
        self.assertEqual(dropped, [agent])

    def test_agent_wording_with_unauthorized_still_merged(self):
        # Agent 標題含「未授權」（弱點類型會被歸 auth），端點相同仍要併掉
        det = _exposure("/svc/v3/api-docs")
        agent = _agent("/svc/v3/api-docs", title="/v3/api-docs 未授權存取")
        kept, dropped = consolidate_cross_layer([det, agent])
        self.assertEqual(dropped, [agent])

    def test_different_endpoint_keeps_both(self):
        # /alt 前綴的 api-docs 沒有對應確定性發現（確定性只探到 /svc），保留
        det = _exposure("/svc/v3/api-docs")
        agent = _agent("/alt/v3/api-docs")
        kept, dropped = consolidate_cross_layer([det, agent])
        self.assertEqual(dropped, [])
        self.assertEqual(len(kept), 2)

    def test_agent_without_endpoint_kept(self):
        det = _exposure("/svc/v3/api-docs")
        agent = _agent("/svc/v3/api-docs")
        agent["evidence_json"]["observed_endpoint"] = ""
        kept, dropped = consolidate_cross_layer([det, agent])
        self.assertEqual(dropped, [])
        self.assertIn(agent, kept)

    def test_non_exposure_deterministic_does_not_merge(self):
        # 同端點但確定性那筆不是「檔案外洩」類（例如 CORS），不以端點併掉 Agent 發現
        cors = {
            "category": "security",
            "severity": "low",
            "rule_id": "api-cors-wildcard",
            "title": "API 允許任意來源跨域",
            "evidence_json": {"endpoint": "/svc/data"},
        }
        agent = _agent("/svc/data", title="SQL 注入")
        kept, dropped = consolidate_cross_layer([cors, agent])
        self.assertEqual(dropped, [])
        self.assertEqual(len(kept), 2)

    def test_agent_only_kept(self):
        agent = _agent("/svc/members/all", title="未授權成員資料 API")
        kept, dropped = consolidate_cross_layer([agent])
        self.assertEqual(dropped, [])
        self.assertIn(agent, kept)
