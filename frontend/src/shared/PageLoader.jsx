// 頁面切換／頁面資料載入的動畫（Signal Bars，2026-10-10 使用者從 Argus Minimal Loading Pack 選定 01）。
// 五根細長條依序起伏，旁邊一行說明文字；對輔助技術宣告為載入中（role="status"）。
// 樣式：會員區外（換頁的 Suspense、公開頁、登入頁）在 05-brand.css；會員區內在
// legacy-member/92-layout.css（舊版範圍會重置外部規則，所以兩處各有一份）。
function PageLoader({ label = "載入中…", className = "" }) {
  return (
    <div className={`ag-page-loader ${className}`} role="status" aria-live="polite">
      <span className="ag-signal" aria-hidden="true">
        <i />
        <i />
        <i />
        <i />
        <i />
      </span>
      <span className="ag-page-loader-label">{label}</span>
    </div>
  );
}

export default PageLoader;
