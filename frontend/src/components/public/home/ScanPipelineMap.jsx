/**
 * 掃描鏈路圖（2026-10-09 重新設計，取代舊的 ScanPipeline／PipelineDiagram）。
 * 參考 TradingGoose 首頁的節點圖做法：圖示方塊＋細灰連線，連線依節點實際位置用曲線連起，
 * 一小段亮色沿線緩慢流動；不用螢光外框與發光圖示。
 * 流程：01 授權閘門 → 02 真實渲染爬取 → 03 三種引擎 → Argus（04 覆蓋檢查、05 證據化、06 評分排序）→ 四項交付。
 * 窄螢幕改成直向清單、不畫連線；偏好減少動態時連線不流動。
 */
import { useEffect, useLayoutEffect, useRef, useState } from "react";

import argusEyeStill from "../../../assets/argus-eye-still.webp";
import {
  BrainIcon,
  BrowserIcon,
  DocIcon,
  ImageIcon,
  RobotIcon,
  RulesIcon,
  ShieldIcon,
  SparkIcon,
  TargetIcon,
} from "../../../shared/LineIcons.jsx";
import { usePrefersReducedMotion } from "./HomeMotion.jsx";

const GATE = { id: "gate", no: "01", Icon: ShieldIcon, title: "授權與安全閘門", desc: "主動測試需先驗證網域" };
const CRAWL = { id: "crawl", no: "02", Icon: BrowserIcon, title: "真實渲染爬取", desc: "Playwright・同網域" };
const ENGINES = [
  { id: "rules", no: "03", Icon: RulesIcon, title: "規則引擎", desc: "五個面向・被動＋主動" },
  { id: "active", no: "03", Icon: TargetIcon, title: "主動安全工具", desc: "Nuclei・路徑探測・需授權" },
  { id: "agent", no: "03", Icon: RobotIcon, title: "Agent 行為測試", desc: "模擬真人操作網站" },
];
const CORE_STEPS = [
  { no: "04", text: "確認每項檢查真的跑完" },
  { no: "05", text: "證據化：位置・截圖・原始內容" },
  { no: "06", text: "評分並排出先修順序" },
];
const OUTPUTS = [
  { id: "report", Icon: ImageIcon, title: "互動報告", desc: "點問題跳到截圖位置" },
  { id: "pdf", Icon: DocIcon, title: "防偽 PDF 報告", desc: "唯一編號・公開查驗" },
  { id: "optimize", Icon: SparkIcon, title: "頁面優化", desc: "產出修正後的頁面" },
  { id: "handoff", Icon: BrainIcon, title: "AI 修復交接", desc: "可直接帶入 AI 助理" },
];

// 連線：[起點節點, 終點節點]
const LINKS = [
  ["gate", "crawl"],
  ...ENGINES.map((e) => ["crawl", e.id]),
  ...ENGINES.map((e) => [e.id, "core"]),
  ...OUTPUTS.map((o) => ["core", o.id]),
];

function Node({ node, nodeRef, size = "md" }) {
  const Icon = node.Icon;
  return (
    <div className={`pm-node is-${size}`}>
      <span className="pm-tile" ref={nodeRef}><Icon /></span>
      <span className="pm-label">
        {node.no && <span className="pm-no">{node.no}</span>}
        <strong>{node.title}</strong>
        <span className="pm-desc">{node.desc}</span>
      </span>
    </div>
  );
}

function useBeams(containerRef, tileRefs) {
  const [geometry, setGeometry] = useState({ width: 0, height: 0, paths: [] });
  useLayoutEffect(() => {
    const container = containerRef.current;
    if (!container) return undefined;
    const update = () => {
      const box = container.getBoundingClientRect();
      const center = (id, side) => {
        const el = tileRefs.current[id];
        if (!el) return null;
        const r = el.getBoundingClientRect();
        const x = side === "out" ? r.right - box.left : r.left - box.left;
        return { x, y: r.top - box.top + r.height / 2 };
      };
      const paths = LINKS.map(([from, to]) => {
        const a = center(from, "out");
        const b = center(to, "in");
        if (!a || !b) return null;
        const mid = (a.x + b.x) / 2;
        return { key: `${from}-${to}`, d: `M ${a.x},${a.y} C ${mid},${a.y} ${mid},${b.y} ${b.x},${b.y}` };
      }).filter(Boolean);
      setGeometry({ width: box.width, height: box.height, paths });
    };
    update();
    const observer = new ResizeObserver(update);
    observer.observe(container);
    return () => observer.disconnect();
  }, [containerRef, tileRefs]);
  return geometry;
}

export default function ScanPipelineMap() {
  const containerRef = useRef(null);
  const tileRefs = useRef({});
  const reduced = usePrefersReducedMotion();
  const { width, height, paths } = useBeams(containerRef, tileRefs);
  const setRef = (id) => (el) => { tileRefs.current[id] = el; };
  const [ready, setReady] = useState(false);
  useEffect(() => { setReady(true); }, []);

  return (
    <div className="pm" ref={containerRef}>
      {ready && width > 0 && (
        <svg className="pm-beams" width={width} height={height} viewBox={`0 0 ${width} ${height}`} aria-hidden="true">
          <defs>
            {!reduced && paths.map((p, i) => (
              <linearGradient key={p.key} id={`pm-g-${i}`} gradientUnits="userSpaceOnUse" x1="0%" x2="0%" y1="0%" y2="0%">
                {/* 顏色由 CSS 的 .pm-stop 給（presentation attribute 不支援 var()） */}
                <stop offset="0%" className="pm-stop" stopOpacity="0" />
                <stop offset="30%" className="pm-stop" stopOpacity="0.9" />
                <stop offset="100%" className="pm-stop" stopOpacity="0" />
                <animate attributeName="x1" values="-20%;100%" dur="4.5s" begin={`${(i % 5) * 0.4}s`} repeatCount="indefinite" />
                <animate attributeName="x2" values="0%;120%" dur="4.5s" begin={`${(i % 5) * 0.4}s`} repeatCount="indefinite" />
              </linearGradient>
            ))}
          </defs>
          {paths.map((p, i) => (
            <g key={p.key}>
              <path d={p.d} className="pm-path" />
              {!reduced && <path d={p.d} className="pm-path-beam" stroke={`url(#pm-g-${i})`} />}
            </g>
          ))}
        </svg>
      )}

      <div className="pm-col">
        <Node node={GATE} nodeRef={setRef("gate")} />
      </div>
      <div className="pm-col">
        <Node node={CRAWL} nodeRef={setRef("crawl")} />
      </div>
      <div className="pm-col is-stack">
        <p className="pm-col-title">03 多引擎交叉診斷</p>
        {ENGINES.map((engine) => (
          <Node key={engine.id} node={{ ...engine, no: "" }} nodeRef={setRef(engine.id)} size="sm" />
        ))}
      </div>
      <div className="pm-col is-core">
        <div className="pm-core">
          <span className="pm-core-tile" ref={setRef("core")}>
            <span className="pm-core-inner">
              <img src={argusEyeStill} alt="Argus" width="256" height="202" />
            </span>
          </span>
          <ol className="pm-core-steps">
            {CORE_STEPS.map((step) => (
              <li key={step.no}><span className="pm-no">{step.no}</span>{step.text}</li>
            ))}
          </ol>
        </div>
      </div>
      <div className="pm-col is-stack">
        <p className="pm-col-title">你會拿到</p>
        {OUTPUTS.map((output) => (
          <Node key={output.id} node={output} nodeRef={setRef(output.id)} size="sm" />
        ))}
      </div>
    </div>
  );
}
