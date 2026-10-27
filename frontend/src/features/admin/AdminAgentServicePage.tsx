import { useCallback, useEffect, useState } from "react";

import {
  type AgentServiceConfig,
  type AgentServiceConfigInput,
  fetchAgentServiceConfig,
  updateAgentServiceConfig,
} from "../../api";
import { AdminField } from "../../components/admin/AdminModal";
import { AdminErrorState, AdminSkeleton } from "../../components/admin/AdminStates";
import { errorDetail, fieldErrors } from "./adminHelpers";

// AI Agent（Strix／argus-agent）服務連線設定（僅超級管理員）。
// 把原本只能改 .env 的 ARGUS_AGENT_SERVICE_* 搬到後台執行期設定：
//   · 空白 base_url ＝ 沿用 .env（向後相容）
//   · enabled=false 且已填 base_url ＝ 掃描時略過 agent 階段（不呼叫、不計費）
//   · 金鑰只進不出：留空保留原金鑰，勾「清除金鑰」才清掉；畫面只顯示是否已設定
// 契約見 backend docs/agent-service-contract.md。

type FormState = {
  enabled: boolean;
  base_url: string;
  timeout_seconds: number;
  verify_tls: boolean;
  api_key: string;
  clear_api_key: boolean;
};

function toForm(cfg: AgentServiceConfig): FormState {
  return {
    enabled: cfg.enabled,
    base_url: cfg.base_url,
    timeout_seconds: cfg.timeout_seconds,
    verify_tls: cfg.verify_tls,
    api_key: "",
    clear_api_key: false,
  };
}

export function AdminAgentServicePage() {
  const [cfg, setCfg] = useState<AgentServiceConfig | null>(null);
  const [form, setForm] = useState<FormState | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const data = await fetchAgentServiceConfig();
      setCfg(data);
      setForm(toForm(data));
    } catch (err) {
      setLoadError(errorDetail(err, "無法載入 AI Agent 服務設定"));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const patch = (next: Partial<FormState>) => {
    setForm((prev) => (prev ? { ...prev, ...next } : prev));
    setSaved(false);
  };

  const onSave = async () => {
    if (!form) return;
    setSaving(true);
    setSaveError(null);
    setErrors({});
    setSaved(false);
    try {
      const payload: AgentServiceConfigInput = {
        enabled: form.enabled,
        base_url: form.base_url.trim(),
        timeout_seconds: form.timeout_seconds,
        verify_tls: form.verify_tls,
        clear_api_key: form.clear_api_key,
      };
      // 只有輸入了新金鑰才送（留空＝保留原金鑰）。
      if (form.api_key && !form.clear_api_key) payload.api_key = form.api_key;
      const updated = await updateAgentServiceConfig(payload);
      setCfg(updated);
      setForm(toForm(updated));
      setSaved(true);
    } catch (err) {
      setErrors(fieldErrors(err));
      setSaveError(errorDetail(err, "儲存失敗"));
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <AdminSkeleton />;
  if (loadError) return <AdminErrorState message={loadError} onRetry={load} />;
  if (!form || !cfg) return null;

  return (
    <div className="admin-page">
      <header className="admin-page-header">
        <h1>AI Agent 服務</h1>
        <p className="admin-page-subtitle">
          設定 Argus 要連到哪個 AI pentest／UX 引擎服務（自家 argus-agent 或 Strix wrapper）。
          正式環境請填 HTTPS 位址。空白則沿用伺服器 .env 設定。
        </p>
      </header>

      <div className="admin-card" style={{ maxWidth: 680 }}>
        <AdminField id="agent-enabled" label="啟用">
          <label className="admin-inline-check">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(e) => patch({ enabled: e.target.checked })}
            />
            <span>啟用後，掃描會呼叫此服務；關閉且已填位址時略過 agent 階段（不計費）。</span>
          </label>
        </AdminField>

        <AdminField
          id="agent-base-url"
          label="服務位址 (base_url)"
          hint="例如 https://strix.example.com。留空＝改用 .env 的 ARGUS_AGENT_SERVICE_URL。"
          error={errors.base_url}
        >
          {(p) => (
            <input
              {...p}
              type="url"
              className="admin-input"
              placeholder="https://strix.example.com"
              value={form.base_url}
              onChange={(e) => patch({ base_url: e.target.value })}
            />
          )}
        </AdminField>

        <AdminField
          id="agent-api-key"
          label="API 金鑰 (Bearer)"
          hint={
            cfg.has_api_key
              ? "已設定金鑰。留空＝保留；輸入新值＝覆寫。"
              : "尚未設定。輸入後以 Bearer 送給服務。"
          }
          error={errors.api_key}
        >
          {(p) => (
            <input
              {...p}
              type="password"
              className="admin-input"
              autoComplete="new-password"
              placeholder={cfg.has_api_key ? "••••••（已設定，留空保留）" : "輸入服務金鑰"}
              value={form.api_key}
              disabled={form.clear_api_key}
              onChange={(e) => patch({ api_key: e.target.value })}
            />
          )}
        </AdminField>

        {cfg.has_api_key && (
          <AdminField id="agent-clear-key" label="清除金鑰">
            <label className="admin-inline-check">
              <input
                type="checkbox"
                checked={form.clear_api_key}
                onChange={(e) => patch({ clear_api_key: e.target.checked, api_key: "" })}
              />
              <span>勾選並儲存後清除現有金鑰（改為不帶 Authorization）。</span>
            </label>
          </AdminField>
        )}

        <AdminField
          id="agent-timeout"
          label="逾時 (秒)"
          hint="同步呼叫逾時；須大於服務單次掃描最長時間（1–7200）。"
          error={errors.timeout_seconds}
        >
          {(p) => (
            <input
              {...p}
              type="number"
              min={1}
              max={7200}
              className="admin-input"
              value={form.timeout_seconds}
              onChange={(e) => patch({ timeout_seconds: Number(e.target.value) })}
            />
          )}
        </AdminField>

        <AdminField id="agent-verify-tls" label="驗證 TLS 憑證">
          <label className="admin-inline-check">
            <input
              type="checkbox"
              checked={form.verify_tls}
              onChange={(e) => patch({ verify_tls: e.target.checked })}
            />
            <span>正式 HTTPS 一律開啟；僅自簽憑證的內網測試才關閉。</span>
          </label>
        </AdminField>

        {saveError && <p className="admin-form-error" role="alert">{saveError}</p>}
        {saved && <p className="admin-form-success" role="status">已儲存。</p>}

        <div className="admin-card-actions">
          <button className="primary-button" onClick={onSave} disabled={saving}>
            {saving ? "儲存中…" : "儲存"}
          </button>
          {cfg.updated_at && (
            <span className="admin-muted">
              最後更新：{new Date(cfg.updated_at).toLocaleString()}
              {cfg.updated_by_username ? `（${cfg.updated_by_username}）` : ""}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
