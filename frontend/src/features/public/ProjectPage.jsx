/**
 * 公開首頁（/project）。最上面的品牌 hero 維持原樣（樣式 21-public／35-public-legacy／70-home）；
 * hero 以下 2026-10-09 依使用者要求重新編排與配色：參考成熟產品首頁的節奏——左文右卡、
 * 單一強調色、細線框。內容精簡成「怎麼做 → 進度 → 拿到什麼 → 安全邊界 → 技術 → 常見問題」，
 * 每一句都對照現有程式。樣式在 styles/73-public-refine.css 的 .home2-*（限縮在 .public-shell 內）。
 */
import { NavLink } from "react-router-dom";

import { useArgusStore } from "../../store";
import argusEyeStill from "../../assets/argus-eye-still.webp";
import argusEye from "../../assets/argus-eye.webp";
import { BRAND_MARKS } from "../../components/public/brandMarks";
import {
  DocIcon,
  GlobeIcon,
  LockIcon,
  ShieldIcon,
  SparkIcon,
  SpiderIcon,
  TargetIcon,
  EyeIcon,
} from "../../shared/LineIcons.jsx";

const STEPS = [
  { no: "01", title: "授權與網域驗證", desc: "只檢查你有權限的網站；主動式測試要先驗證網域所有權。" },
  { no: "02", title: "真實瀏覽器走訪", desc: "以 Playwright 渲染每一頁並截圖，整站最多 50 頁。" },
  { no: "03", title: "五個面向同時檢查", desc: "規則引擎搭配 axe-core、PageSpeed Insights 等業界標準工具。" },
  { no: "04", title: "證據與排序", desc: "每個問題附位置與證據，依影響排好先修哪一個。" },
];

// 產品預覽：示意畫面，四筆對應真實規則
const DEMO_FINDINGS = [
  { sev: "high", tag: "高", cat: "資安", title: "頁面未使用 HTTPS", meta: "3 個頁面" },
  { sev: "medium", tag: "中", cat: "GEO", title: "缺少 JSON-LD 結構化資料", meta: "AI 無法辨識實體" },
  { sev: "low", tag: "低", cat: "SEO", title: "圖片缺少替代文字", meta: "3 張圖片" },
  { sev: "info", tag: "資訊", cat: "AEO", title: "尚未提供 llms.txt", meta: "給 AI 爬蟲的說明" },
];

const SAFETY = [
  { Icon: LockIcon, title: "授權紀錄", desc: "每次送出都記錄時間、IP 與授權聲明。" },
  { Icon: EyeIcon, title: "被動為預設", desc: "只讀取公開回應；主動測試需先驗證網域。" },
  { Icon: GlobeIcon, title: "同網域範圍", desc: "只走訪授權網站同網域的頁面。" },
  { Icon: ShieldIcon, title: "SSRF 防護", desc: "入口、轉址與子資源都檢查是否為公開位址。" },
];

// 都是 repo 實際使用的技術（package.json、pyproject.toml、k8s/、.github/workflows）
const TECH = [
  "React", "Django", "Celery", "Redis", "PostgreSQL", "Playwright",
  "Kubernetes", "Argo CD", "Cloudflare", "Docker", "NGINX", "GitHub Actions",
];

const FAQ = [
  {
    q: "快速檢查和完整掃描差在哪？",
    a: "快速檢查免登入、不扣點，只分析單一頁面；完整掃描以真實瀏覽器走訪整站、逐頁截圖，並產出互動報告與 PDF。",
  },
  {
    q: "完整掃描怎麼計費？",
    a: "每頁每個面向 2 coin，只勾需要的面向。建立時依最大頁數預扣，完成後依實際頁數退回；失敗或取消全額退回。第一次完整掃描免費，登入後每月另贈 200 coin。",
  },
  {
    q: "可以掃描不是我的網站嗎？",
    a: "只限你擁有或取得授權的網站。預設為被動模式；主動式資安測試必須先完成網域所有權驗證，所有操作都留有紀錄。",
  },
  {
    q: "怎麼確認收到的報告是真的？",
    a: "每份 PDF 報告都有唯一編號，任何人都能在「報告查驗」頁核對內容是否被改過，不需要登入。",
  },
];

function Eyebrow({ children }) {
  return <p className="home2-eyebrow">{children}</p>;
}

function Dash({ children }) {
  return (
    <li>
      <span className="home2-dash" aria-hidden="true" />
      {children}
    </li>
  );
}

function ScanDemo() {
  return (
    <div className="home2-demo">
      <div className="home2-demo-bar">
        <span className="home2-demo-url"><LockIcon />example.com</span>
        <span className="home2-demo-tag">示意</span>
      </div>
      <div className="home2-demo-phase">
        <span className="home2-demo-phase-icon"><SpiderIcon /></span>
        <span>
          <strong>走訪頁面</strong>
          <span className="home2-muted">12 / 50 頁</span>
        </span>
        <span className="home2-demo-live">進行中</span>
      </div>
      <div className="home2-demo-progress" role="presentation"><span /></div>
      <ul className="home2-demo-list">
        {DEMO_FINDINGS.map((f) => (
          <li key={f.title}>
            <span className={`home2-sev is-${f.sev}`}>{f.tag}</span>
            <span className="home2-demo-main">
              <span className="home2-demo-title">{f.title}</span>
              <span className="home2-muted">{f.meta}</span>
            </span>
            <span className="home2-demo-cat">{f.cat}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function EvidenceCard() {
  return (
    <figure className="home2-card home2-evidence">
      <figcaption className="home2-card-cap">報告中的一筆問題（示意）</figcaption>
      <p className="home2-evidence-title">
        <span className="home2-sev is-high">高</span>
        缺少 Content-Security-Policy 標頭
      </p>
      <dl className="home2-kv">
        <div><dt>頁面</dt><dd>https://example.com/</dd></div>
        <div><dt>證據</dt><dd>回應標頭中找不到 Content-Security-Policy</dd></div>
        <div><dt>修法</dt><dd>在伺服器回應加入 CSP，先以 Report-Only 觀察再正式啟用</dd></div>
      </dl>
    </figure>
  );
}

function VerifyCard() {
  return (
    <figure className="home2-card home2-verify">
      <figcaption className="home2-card-cap">報告查驗（示意）</figcaption>
      <div className="home2-verify-row">
        <DocIcon />
        <span>
          <strong>網站健檢報告.pdf</strong>
          <span className="home2-muted">唯一報告編號＋內容指紋</span>
        </span>
      </div>
      <p className="home2-verify-ok">內容與原始報告一致</p>
    </figure>
  );
}

function CompareCard() {
  return (
    <figure className="home2-card home2-compare">
      <figcaption className="home2-card-cap">頁面優化前後對照（示意）</figcaption>
      <div className="home2-compare-grid">
        {["原始頁面", "優化後"].map((label, i) => (
          <div className={`home2-compare-pane${i ? " is-after" : ""}`} key={label}>
            <span className="home2-compare-label">{label}</span>
            <span className="home2-compare-block is-hero" />
            <span className="home2-compare-block" />
            <span className="home2-compare-block is-short" />
          </div>
        ))}
      </div>
    </figure>
  );
}

const FEATURES = [
  {
    Icon: TargetIcon,
    eyebrow: "互動報告",
    title: "截圖上直接框出問題",
    desc: "在逐頁截圖上框出實際元素，點問題就跳到位置；可依面向與嚴重度篩選。",
    points: ["每個問題附位置、證據與觸發規則", "同一處設定造成的問題合併成「改一處一起解決」", "分數說明逐項列出扣分來源"],
    Visual: EvidenceCard,
  },
  {
    Icon: DocIcon,
    eyebrow: "PDF 報告",
    title: "可交付、可查驗",
    desc: "一鍵匯出 PDF，開頭先列最該處理的三件事；收件者可公開核對內容沒被改過。",
    points: ["每項附修好後如何確認", "唯一報告編號，查驗不需登入", "適合直接交給主管或外包廠商"],
    Visual: VerifyCard,
  },
  {
    Icon: SparkIcon,
    eyebrow: "頁面優化",
    title: "直接產出修正後的頁面",
    desc: "針對單一頁面產出優化版，前後對照並列出每一處修改與原因。",
    points: ["桌面與手機前後對照", "修改依視覺、SEO、無障礙、效能分組", "可分享連結或下載優化版 HTML"],
    Visual: CompareCard,
  },
];

export function ProjectPage() {
  const accessToken = useArgusStore((s) => s.accessToken);
  const startTo = accessToken ? "/dashboard" : "/login";
  return (
    <>
      {/* 最上面的品牌 hero 維持改版前原樣（使用者指定只改下方區塊） */}
      <div className="public-page">
        <section className="public-hero public-hero--console">
          <div className="public-hero-bg" aria-hidden="true">
            <span className="hero-orb hero-orb-1" />
            <span className="hero-orb hero-orb-2" />
            <span className="hero-orb hero-orb-3" />
            <span className="hero-grid" />
            <span className="hero-scan" />
            <span className="hero-corner tl" />
            <span className="hero-corner tr" />
            <span className="hero-corner bl" />
            <span className="hero-corner br" />
          </div>
          <div className="public-hero-content">
            {/* 品牌識別：會動的 Argus 之眼 ＋ 藝術字。
                之眼用 <picture>，偏好減少動態者自動換靜態首幀且不下載動態版。 */}
            <div className="public-hero-brand">
              <picture className="public-hero-eye">
                <source media="(prefers-reduced-motion: reduce)" srcSet={argusEyeStill} />
                <img src={argusEye} alt="" width="256" height="202" />
              </picture>
              <span className="public-hero-wordmark" aria-label="ARGUS">
                {"ARGUS".split("").map((ch, i) => (
                  <span key={`${ch}-${i}`} style={{ animationDelay: `${i * 0.08}s` }}>{ch}</span>
                ))}
              </span>
            </div>
            <span className="public-hero-eyebrow">掃描 · 洞察 · 證據</span>
            <h1 className="public-hero-title">
              一鍵看見<span className="hero-grad">網站的所有問題</span>
            </h1>
            <p className="public-hero-sub">
              輸入網址，找出網站在<strong>搜尋、體驗與資安</strong>上的問題，並排好該先處理哪一個。
            </p>
            <p className="public-hero-sub is-highlight">
              不只列出問題——修正要用的檔案，直接生給你。
            </p>
            <div className="public-hero-actions">
              <NavLink to="/login" className="public-cta-primary">登入進行詳細檢查 →</NavLink>
              <NavLink to="/free-tools" className="public-cta-ghost">免登入先試單頁檢查</NavLink>
            </div>
          </div>
        </section>
      </div>

    <div className="home2">
      <section className="home2-section home2-split">
        <div className="home2-split-text">
          <Eyebrow>運作方式</Eyebrow>
          <h2 className="home2-h2">從網址到修正清單</h2>
          <p className="home2-p">
            Argus 用真實瀏覽器走訪你的網站，五個面向同時檢查，再整理成有證據、有順序的修正清單。
          </p>
        </div>
        <ol className="home2-card home2-steps">
          {STEPS.map((s) => (
            <li key={s.no}>
              <span className="home2-step-no">{s.no}</span>
              <span>
                <strong>{s.title}</strong>
                <span className="home2-muted">{s.desc}</span>
              </span>
            </li>
          ))}
        </ol>
      </section>

      <section className="home2-section home2-split is-reverse">
        <ScanDemo />
        <div className="home2-split-text">
          <Eyebrow>即時進度</Eyebrow>
          <h2 className="home2-h2">每一步都看得到</h2>
          <p className="home2-p">掃描在背景執行，不必盯著畫面；走訪、檢查、量測各階段的進度即時更新。</p>
          <ul className="home2-dashes">
            <Dash>問題依嚴重度與面向標示</Dash>
            <Dash>檢查沒跑完會明講，不當成沒問題</Dash>
            <Dash>失敗或取消，預扣點數全額退回</Dash>
          </ul>
        </div>
      </section>

      <section className="home2-section">
        <header className="home2-center-head">
          <Eyebrow>你會拿到什麼</Eyebrow>
          <h2 className="home2-h2 is-large">不只是一份問題清單</h2>
          <p className="home2-p">每個問題都能追溯、能排序、能修。</p>
        </header>
        <div className="home2-features">
          {FEATURES.map(({ Icon, eyebrow, title, desc, points, Visual }, i) => (
            <div className={`home2-feature${i % 2 ? " is-reverse" : ""}`} key={eyebrow}>
              <Visual />
              <article className="home2-card home2-feature-card">
                <p className="home2-feature-head">
                  <span className="home2-icon-box"><Icon /></span>
                  <span className="home2-eyebrow">{eyebrow}</span>
                </p>
                <h3 className="home2-h3">{title}</h3>
                <p className="home2-p">{desc}</p>
                <ul className="home2-dashes">
                  {points.map((p) => <Dash key={p}>{p}</Dash>)}
                </ul>
              </article>
            </div>
          ))}
        </div>
      </section>

      <section className="home2-section">
        <header className="home2-center-head">
          <Eyebrow>安全邊界</Eyebrow>
          <h2 className="home2-h2">只檢查你有權限的網站</h2>
        </header>
        <ul className="home2-safety">
          {SAFETY.map(({ Icon, title, desc }) => (
            <li key={title}>
              <span className="home2-icon-box"><Icon /></span>
              <strong>{title}</strong>
              <span className="home2-muted">{desc}</span>
            </li>
          ))}
        </ul>
      </section>

      <section className="home2-section home2-split">
        <div className="home2-split-text">
          <Eyebrow>技術</Eyebrow>
          <h2 className="home2-h2">以成熟的開源技術打造</h2>
          <ul className="home2-dashes">
            <Dash>React 前端、Django API、Celery 背景工作</Dash>
            <Dash>Playwright 驅動真實瀏覽器</Dash>
            <Dash>Kubernetes 部署，Argo CD 持續交付</Dash>
          </ul>
        </div>
        <ul className="home2-logos" aria-label="使用的技術">
          {TECH.map((name) => {
            const mark = BRAND_MARKS[name];
            return (
              <li key={name}>
                <svg viewBox={mark.viewBox} aria-hidden="true" focusable="false">{mark.node}</svg>
                <span>{name}</span>
              </li>
            );
          })}
        </ul>
      </section>

      <section className="home2-section home2-faq-wrap">
        <header className="home2-center-head">
          <Eyebrow>常見問題</Eyebrow>
        </header>
        <div className="home2-faq">
          {FAQ.map((item) => (
            <details key={item.q}>
              <summary>{item.q}</summary>
              <p>{item.a}</p>
            </details>
          ))}
        </div>
      </section>

      <section className="home2-section">
        <div className="home2-cta">
          <span className="home2-grid" aria-hidden="true" />
          <h2 className="home2-h3">準備好看見你的網站了嗎？</h2>
          <p className="home2-muted">第一次完整掃描免費。</p>
          <div className="home2-actions">
            <NavLink to={startTo} className="home2-btn is-primary">開始掃描</NavLink>
            <NavLink to="/purchase" className="home2-btn">查看方案</NavLink>
          </div>
        </div>
      </section>
    </div>
    </>
  );
}
