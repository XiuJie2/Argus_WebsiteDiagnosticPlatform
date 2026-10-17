"""未授權存取探測分析測試（security/authz_probe.py）。

重點在誤報防線：公開 JSON API 很常見，只有「成批記錄＋身分欄位＋內部帳號欄位」才算。
"""

from __future__ import annotations

import json

from django.test import SimpleTestCase

from apps.scans.security.authz_probe import analyze_unauthorized_results


def _result(body, *, status=200, ctype="application/json", url="https://site.example.test/svc/members/all"):
    return {"url": url, "status": status, "content_type": ctype,
            "body": body if isinstance(body, str) else json.dumps(body)}


# 成批成員記錄：身分（name）＋內部（memberId／roleId／啟用狀態）→ 應報
_MEMBER_DUMP = {
    "result": True,
    "data": [
        {"memberId": "M001", "name": "甲", "roleId": 1, "roleName": "管理員", "isActive": True},
        {"memberId": "M002", "name": "乙", "roleId": 2, "roleName": "助理", "isActive": False},
    ],
}


class AnalyzeUnauthorizedResultsTests(SimpleTestCase):
    def test_member_dump_flagged(self):
        findings = analyze_unauthorized_results([_result(_MEMBER_DUMP)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "security-unauth-api-records")
        # 名單無 email／電話 → medium（保守）
        self.assertEqual(findings[0]["severity"], "medium")

    def test_pii_escalates_to_high(self):
        body = {
            "data": [
                {"memberId": "M001", "name": "甲", "roleName": "師", "email": "a@x.example.test"},
                {"memberId": "M002", "name": "乙", "roleName": "師", "email": "b@x.example.test"},
            ]
        }
        findings = analyze_unauthorized_results([_result(body)])
        self.assertEqual(findings[0]["severity"], "high")

    def test_password_field_escalates_to_high(self):
        body = [
            {"userId": 1, "username": "a", "password": "x"},
            {"userId": 2, "username": "b", "password": "y"},
        ]
        findings = analyze_unauthorized_results([_result(body)])
        self.assertEqual(findings[0]["severity"], "high")

    # —— 誤報防線 ——
    def test_public_directory_without_internal_keys_not_flagged(self):
        # 公開人員目錄：只有姓名職稱、沒有內部 id／帳號狀態 → 不報
        body = [
            {"name": "張老師", "title": "教授"},
            {"name": "李老師", "title": "副教授"},
        ]
        self.assertEqual(analyze_unauthorized_results([_result(body)]), [])

    def test_public_product_list_not_flagged(self):
        # 公開商品清單：有 id 但沒有身分欄位 → 不報
        body = {"data": [{"id": 1, "price": 100}, {"id": 2, "price": 200}]}
        self.assertEqual(analyze_unauthorized_results([_result(body)]), [])

    def test_single_record_not_flagged(self):
        # 單筆（例如自己的個人資料端點）不是成批外洩
        body = [{"memberId": "M001", "name": "甲", "roleName": "師"}]
        self.assertEqual(analyze_unauthorized_results([_result(body)]), [])

    def test_non_200_not_flagged(self):
        self.assertEqual(
            analyze_unauthorized_results([_result(_MEMBER_DUMP, status=401)]), []
        )

    def test_non_json_not_flagged(self):
        self.assertEqual(
            analyze_unauthorized_results([_result("<html>hi</html>", ctype="text/html")]), []
        )

    def test_empty_results(self):
        self.assertEqual(analyze_unauthorized_results([]), [])
