import { describe, expect, it } from "vitest";

import { scanProgress } from "./ScanExperience";

describe("scanProgress 頁面分析合併步驟", () => {
  const steps = ["crawl", "analyze_pages", "deep_security", "scoring"];

  it("標題與說明改用目前分析的維度", () => {
    const p = scanProgress("scanning", { steps, step: "analyze_pages", step_detail: "geo", step_done: 3, step_total: 10 });
    expect(p.current.key).toBe("analyze_pages");
    expect(p.current.label).toBe("頁面分析");
    expect(p.current.title).toBe("分析 GEO");
    expect(p.stepFrac).toBeCloseTo(0.3);
  });

  it("沒有 step_detail 時顯示通用說明", () => {
    const p = scanProgress("scanning", { steps, step: "analyze_pages" });
    expect(p.current.title).toBe("分析頁面");
  });

  it("舊任務的逐維度步驟仍可顯示", () => {
    const p = scanProgress("scanning", { steps: ["crawl", "analyze_seo", "analyze_ux", "scoring"], step: "analyze_ux" });
    expect(p.current.title).toBe("分析 UX");
    expect(p.currentIdx).toBe(3);
  });
});
