/**
 * 快速檢查頁「網站測速」的 Google PageSpeed Insights 結果（2026-10-09）。
 * 後端 speed-test 會回 `pagespeed`：unavailable（平台沒設金鑰，不顯示）／pending（附 job，背景量測中）／
 * done（附 report，格式同 ScanJob.performance_report）／failed（附 reason）。
 * pending 時每 3 秒輪詢 `/insights/speed-test/pagespeed/<job>/`，最多 2.5 分鐘。
 */
import { useEffect, useState } from "react";

import { api } from "../../api";

const POLL_MS = 3000;
const MAX_POLLS = 50;

const SCORE_LABELS = [
  ["performance", "效能"],
  ["accessibility", "無障礙"],
  ["best-practices", "最佳做法"],
  ["seo", "SEO"],
];

function scoreTone(score) {
  if (score >= 90) return "good";
  if (score >= 50) return "warn";
  return "bad";
}

function formatField(name, value) {
  if (name === "CLS") return value.toFixed(2);
  return value >= 1000 ? `${(value / 1000).toFixed(1)} 秒` : `${value} 毫秒`;
}

function usePageSpeed(initial) {
  const [state, setState] = useState(initial);
  useEffect(() => {
    setState(initial);
    if (initial?.status !== "pending" || !initial.job) return undefined;
    let polls = 0;
    let cancelled = false;
    let timer;
    const poll = async () => {
      polls += 1;
      try {
        const res = await api.get(`/insights/speed-test/pagespeed/${initial.job}/`);
        if (cancelled) return;
        if (res.data.status !== "pending") {
          setState(res.data);
          return;
        }
      } catch {
        if (cancelled) return;
        setState({ status: "failed", reason: "無法取得 Google 量測結果，請重新測速。" });
        return;
      }
      if (polls >= MAX_POLLS) {
        setState({ status: "failed", reason: "Google 量測逾時，請稍後再測一次。" });
        return;
      }
      timer = setTimeout(poll, POLL_MS);
    };
    timer = setTimeout(poll, POLL_MS);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [initial]);
  return state;
}

export default function PageSpeedResult({ pagespeed }) {
  const state = usePageSpeed(pagespeed);
  if (!state || state.status === "unavailable") return null;

  return (
    <section className="insight-psi" aria-live="polite">
      <h3 className="insight-psi-title">Google PageSpeed Insights（行動版）</h3>
      {state.status === "pending" && (
        <p className="insight-note">Google 正在量測，約需 20～60 秒，結果出來會自動顯示。</p>
      )}
      {state.status === "failed" && (
        <p className="insight-note">這次沒有取得 Google 量測結果：{state.reason || "原因不明"}</p>
      )}
      {state.status === "done" && <PageSpeedReport report={state.report} cached={state.cached} />}
    </section>
  );
}

function PageSpeedReport({ report, cached }) {
  const lab = report?.lab || {};
  const field = report?.field || {};
  const scores = lab.scores || {};
  const metrics = Object.values(lab.metrics || {});
  const fieldMetrics = Object.entries(field.metrics || {});
  return (
    <>
      <p className="insight-note">
        Lighthouse {lab.version || ""} 以模擬行動裝置量測一次，數值會隨網路與伺服器狀況浮動。
        {cached && "（10 分鐘內測過同一網址，沿用上次結果。）"}
      </p>
      {lab.error ? (
        <p className="insight-note">Lighthouse 無法完成量測（{lab.error}）。</p>
      ) : (
        <div className="insight-metrics-grid">
          {SCORE_LABELS.filter(([key]) => scores[key] != null).map(([key, label]) => (
            <div key={key} className={`insight-psi-score is-${scoreTone(scores[key])}`}>
              <span>{label}</span>
              <strong>{scores[key]}</strong>
            </div>
          ))}
        </div>
      )}
      {metrics.length > 0 && (
        <div className="insight-metrics-grid">
          {metrics.map((metric) => (
            <div key={metric.label}>
              <span>{metric.label}</span>
              <strong>{metric.display || "—"}</strong>
            </div>
          ))}
        </div>
      )}
      <h4 className="insight-psi-subtitle">Chrome 真實使用者體驗（CrUX）</h4>
      {fieldMetrics.length > 0 ? (
        <>
          <p className="insight-note">
            過去 28 天的第 75 百分位。
            {field.scope === "origin" && "這個網址的資料不足，以下是整個網站的資料。"}
          </p>
          <div className="insight-metrics-grid">
            {fieldMetrics.map(([name, item]) => (
              <div key={name}>
                <span>{name}</span>
                <strong>
                  {formatField(name, item.p75)}
                  {item.category_label && `（${item.category_label}）`}
                </strong>
              </div>
            ))}
          </div>
        </>
      ) : (
        <p className="insight-note">{field.reason || "這個網站的真實使用者資料不足。"}</p>
      )}
      {lab.opportunities?.length > 0 && (
        <>
          <h4 className="insight-psi-subtitle">最值得改善的項目</h4>
          <ul className="insight-finding-list">
            {lab.opportunities.map((item) => (
              <li key={item.id}>
                <strong>{item.title}</strong>
                {item.display && <span>{item.display}</span>}
              </li>
            ))}
          </ul>
        </>
      )}
    </>
  );
}
