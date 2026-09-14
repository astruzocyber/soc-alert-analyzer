// xlsx.js
// Builds the 4-tab .xlsx workbook client-side with ExcelJS, matching the
// formatting conventions from build_granular_tabs.py: navy header row, wrap
// text, frozen header, autofilter, color-coded Critical Level and
// Classification fills, computed row heights, and a TOTAL row using a real
// =SUM() formula. Produces an in-memory Blob; never uploads anything.

(function (global) {
  "use strict";

  const HEADERS = ["Full Alert", "Critical Level", "Count", "Classification", "Explanation"];
  const WIDTHS = [70, 16, 10, 26, 95];
  const NAVY = "FF1F3A5F";

  const LEVEL_FILL = {
    "Critical": "FFF8CBCB",
    "High": "FFFCE4C6",
    "Medium": "FFFFF2CC",
    "Low": "FFD9EAD3",
    "Unclassified, review required": "FFD9C9EF", // distinct color, easy to triage first
  };
  const CLASS_FILL = {
    "True Positive": "FFF4CCCC",
    "True Positive (Likely)": "FFF4CCCC",
    "True Positive (Blocked)": "FFFCE4C6",
    "False Positive (Likely)": "FFD9EAD3",
    "N/A (No Occurrences This Period)": "FFEFEFEF",
    "Needs Manual Classification": "FFD9C9EF", // distinct, visually separate from TP/FP fills
  };

  function classFillFor(classification) {
    if (CLASS_FILL[classification]) return CLASS_FILL[classification];
    if (classification && classification.startsWith("Needs Manual Classification")) return "FFD9C9EF";
    if (classification && classification.includes("Mixed")) return "FFE0E0F8";
    return null;
  }

  function levelFillFor(level) {
    return LEVEL_FILL[level] || null;
  }

  function writeMatrixSheet(workbook, title, rows, note) {
    const ws = workbook.addWorksheet(title, { views: [{ state: "frozen", ySplit: 2 }] });

    ws.mergeCells(1, 1, 1, 5);
    const noteCell = ws.getCell(1, 1);
    noteCell.value = note;
    noteCell.font = { name: "Arial", italic: true, size: 9, color: { argb: "FF555555" } };
    noteCell.alignment = { wrapText: true, vertical: "top" };
    ws.getRow(1).height = 30;

    const headerRow = 2;
    HEADERS.forEach((h, idx) => {
      const c = idx + 1;
      const cell = ws.getCell(headerRow, c);
      cell.value = h;
      cell.font = { name: "Arial", bold: true, color: { argb: "FFFFFFFF" }, size: 11 };
      cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: NAVY } };
      cell.alignment = { vertical: "middle", horizontal: c === 3 ? "center" : "left" };
      cell.border = thinBorder();
    });
    ws.getRow(headerRow).height = 20;

    let i = headerRow + 1;
    for (const r of rows) {
      ws.getCell(i, 1).value = r.alert;
      ws.getCell(i, 2).value = r.level;
      ws.getCell(i, 3).value = r.count;
      ws.getCell(i, 4).value = r.classification;
      ws.getCell(i, 5).value = r.explanation;

      ws.getCell(i, 1).font = { name: "Arial", size: 9 };
      ws.getCell(i, 2).font = { name: "Arial", size: 9, bold: true };
      ws.getCell(i, 3).font = { name: "Arial", size: 9, bold: true };
      ws.getCell(i, 4).font = { name: "Arial", size: 9, bold: true };
      ws.getCell(i, 5).font = { name: "Arial", size: 9 };

      ws.getCell(i, 1).alignment = { wrapText: true, vertical: "top" };
      ws.getCell(i, 2).alignment = { wrapText: true, vertical: "top", horizontal: "center" };
      ws.getCell(i, 3).alignment = { wrapText: true, vertical: "top", horizontal: "center" };
      ws.getCell(i, 4).alignment = { wrapText: true, vertical: "top", horizontal: "center" };
      ws.getCell(i, 5).alignment = { wrapText: true, vertical: "top" };

      const lvlFill = levelFillFor(r.level);
      if (lvlFill) ws.getCell(i, 2).fill = { type: "pattern", pattern: "solid", fgColor: { argb: lvlFill } };
      const clsFill = classFillFor(r.classification);
      if (clsFill) ws.getCell(i, 4).fill = { type: "pattern", pattern: "solid", fgColor: { argb: clsFill } };

      for (let c = 1; c <= 5; c++) ws.getCell(i, c).border = thinBorder();

      const alertLines = Math.max(1, Math.ceil((r.alert || "").length / 90));
      const expLines = Math.max(1, Math.ceil((r.explanation || "").length / 95));
      const lines = Math.max(alertLines, expLines, 2);
      ws.getRow(i).height = Math.max(26, lines * 12.0);

      i += 1;
    }

    const lastDataRow = headerRow + rows.length;
    const totalRow = lastDataRow + 1;
    ws.getCell(totalRow, 1).value = "TOTAL";
    ws.getCell(totalRow, 1).font = { name: "Arial", bold: true, size: 11 };
    ws.getCell(totalRow, 1).alignment = { horizontal: "right" };

    const sumCell = ws.getCell(totalRow, 3);
    sumCell.value = { formula: `SUM(C${headerRow + 1}:C${lastDataRow})` };
    sumCell.font = { name: "Arial", bold: true, size: 11 };
    sumCell.alignment = { horizontal: "center" };

    for (let c = 1; c <= 5; c++) {
      ws.getCell(totalRow, c).fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FFE8EEF4" } };
      ws.getCell(totalRow, c).border = thinBorder();
    }

    WIDTHS.forEach((w, idx) => { ws.getColumn(idx + 1).width = w; });
    ws.autoFilter = { from: { row: headerRow, column: 1 }, to: { row: lastDataRow, column: 5 } };
    return ws;
  }

  function thinBorder() {
    const side = { style: "thin", color: { argb: "FFD9D9D9" } };
    return { top: side, bottom: side, left: side, right: side };
  }

  function writeMethodologySheet(workbook, meta) {
    const ws = workbook.addWorksheet("Methodology & Notes");
    ws.getColumn(1).width = 130;
    const lines = [
      ["SOC Alert Analysis Matrix: Methodology & Notes", true, 13],
      ["", false, 10],
      ["Generated entirely client-side in the browser. No source CSV data or derived output ever left the", false, 10],
      ["browser during generation; see SECURITY.md in the repository for the full data handling model.", false, 10],
      ["", false, 10],
      [`Files processed: ${meta.fileNames.join(", ")}`, false, 10],
      [`Total alert types seen: ${meta.subjectCount}`, false, 10],
      [`Known (purpose-built) alert types matched: ${meta.knownCount}`, false, 10],
      [`Unknown alert types handled by the generic fallback: ${meta.fallbackCount}`, false, 10],
      ["", false, 10],
      ["Reconciliation check (performed before this file was generated):", true, 11],
      [`  Master matrix total: ${meta.reconcile.masterTotal.toLocaleString()}`, false, 10],
      [`  Network Activity total: ${meta.reconcile.netTotal.toLocaleString()}`, false, 10],
      [`  Host Activity total: ${meta.reconcile.hostTotal.toLocaleString()}`, false, 10],
      [`  Network + Host = ${(meta.reconcile.netTotal + meta.reconcile.hostTotal).toLocaleString()}, ` +
       `matching the master matrix total (${meta.reconcile.grandTotal.toLocaleString()}) exactly. ` +
       "Every row (known type or generic fallback) is categorized into exactly one of the two detail tabs.",
       false, 10],
      ["", false, 10],
      ["Entity level granularity:", true, 11],
      ["  The Network Activity and Host Activity tabs contain one row per unique combination of the identifying", false, 10],
      ["  fields for each alert type (for example internal host plus external IP plus port for Palo Alto network", false, 10],
      ["  alerts, host name plus file path for Cortex XDR, or user account for Windows account events). Repeated", false, 10],
      ["  occurrences of the exact same combination are merged into one row, with Count summed across all of them", false, 10],
      ["  using the row's own Count or eventcount field where present, falling back to counting raw table rows", false, 10],
      ["  only when neither field exists.", false, 10],
      ["", false, 10],
      ["Generic fallback (unknown alert types):", true, 11],
      ["  Any alert type (Subject) not in the purpose-built extractor and classifier list is handled by a", false, 10],
      ["  schema-agnostic fallback: every field value in each row is scanned with regular expressions for", false, 10],
      ["  IP-shaped and hostname-shaped tokens, rows are grouped by the distinct set of tokens found, and any", false, 10],
      ["  Count or eventcount field present is still summed by field name. These rows are given the Critical", false, 10],
      ["  Level 'Unclassified, review required' and Classification 'Needs Manual Classification', with a fill", false, 10],
      ["  color distinct from every other classification so they are easy to find and triage first. See the", false, 10],
      ["  project README for the step-by-step process to graduate an alert type from this fallback to a proper", false, 10],
      ["  purpose-built extractor and classifier once its fields have been reviewed.", false, 10],
      ["", false, 10],
      ["Multi-file handling:", true, 11],
      [`  ${meta.fileNames.length} file(s) were uploaded and merged. For any alert type appearing in more than`, false, 10],
      ["  one file, a pairwise timestamp overlap check was run across every pair of files containing that alert", false, 10],
      ["  type before merging. Overlapping pairs were flagged for manual resolution rather than silently merged,", false, 10],
      ["  to avoid double counting or silently dropping data.", false, 10],
      [meta.conflictSummary, false, 10],
      ["", false, 10],
      ["No em dashes (the character U+2014) are used anywhere in this workbook's generated text; the app", false, 10],
      ["scans every generated string for this character before enabling the download button.", false, 10],
    ];
    let r = 1;
    for (const [text, bold, size] of lines) {
      const cell = ws.getCell(r, 1);
      cell.value = text;
      cell.font = { name: "Arial", bold, size };
      cell.alignment = { wrapText: true, vertical: "top" };
      r += 1;
    }
    return ws;
  }

  // Builds the full workbook and returns a Blob ready for a download link.
  // rows = { masterRows, netRows, hostRows }, meta = extra info for the
  // Methodology tab. onProgress(stage, current, total) optional callback for
  // the large-row-count progress indicator.
  async function buildWorkbook(rowsBundle, meta, onProgress) {
    const workbook = new ExcelJS.Workbook();
    workbook.creator = "SOC Alert Analyzer (client-side)";
    workbook.created = new Date();

    if (onProgress) onProgress("Writing Alert Analysis Matrix tab", 0, 4);
    writeMatrixSheet(workbook, "Alert Analysis Matrix", rowsBundle.masterRows,
      "Alert Analysis Matrix: one row per alert rule (alert type), Count summed across all occurrences and " +
      "all uploaded files for that alert type. Critical Level is a static severity rating independent of " +
      "whether this period's occurrences look like true or false positives. See the Network Activity and " +
      "Host Activity tabs for entity level detail.");

    if (onProgress) onProgress("Writing Network Activity tab", 1, 4);
    await yieldToUI();
    writeMatrixSheet(workbook, "Network Activity", rowsBundle.netRows,
      "Network Activity, entity level detail: one row per unique combination of internal host, external " +
      "indicator, port, or destination observed within each Palo Alto or Fortinet alert rule (or, for an " +
      "unknown alert type handled by the generic fallback, the distinct IP-shaped tokens found in its rows). " +
      "Repeated occurrences of the exact same combination are merged into one row, with Count reflecting the " +
      "true total and the timestamp range shown in brackets at the end of the Full Alert text where available.");

    if (onProgress) onProgress("Writing Host Activity tab", 2, 4);
    await yieldToUI();
    writeMatrixSheet(workbook, "Host Activity", rowsBundle.hostRows,
      "Host Activity, entity level detail: one row per unique combination of host name, user account, or file " +
      "path observed within each Cortex XDR or Windows alert rule (or, for an unknown alert type handled by the " +
      "generic fallback, the distinct hostname-shaped tokens found in its rows). Repeated occurrences of the " +
      "exact same combination are merged into one row, with Count reflecting the true total and the timestamp " +
      "range shown in brackets at the end of the Full Alert text where available.");

    if (onProgress) onProgress("Writing Methodology & Notes tab", 3, 4);
    await yieldToUI();
    writeMethodologySheet(workbook, meta);

    if (onProgress) onProgress("Finalizing workbook", 4, 4);
    await yieldToUI();
    const buffer = await workbook.xlsx.writeBuffer();
    return new Blob([buffer], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" });
  }

  function yieldToUI() {
    return new Promise((resolve) => setTimeout(resolve, 0));
  }

  global.SocXlsx = { buildWorkbook };
})(window);
