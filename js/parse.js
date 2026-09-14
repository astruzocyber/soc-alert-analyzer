// parse.js
// Direct JS port of parse_both.py (parse_body, split_line, parse_time_range).
// Uses PapaParse (vendored, js/lib/papaparse.min.js) for the outer CSV parse
// only. No network calls anywhere in this file.

(function (global) {
  "use strict";

  const META_KEYS = [
    "Saved Search", "Description", "Time Range", "Run Frequency",
    "Notification Threshold", "Run At", "Scheduled By",
  ];

  function splitLine(line) {
    let parts = line.split("\t").map((p) => p.trim());
    while (parts.length && parts[parts.length - 1] === "") parts.pop();
    return parts;
  }

  // Port of parse_body(): reconstructs true row boundaries using the table's
  // own "#" index (increments by exactly 1 starting at 1), buffering physical
  // lines until the next expected index appears. This is what correctly
  // handles cells with an embedded newline (e.g. Cortex XDR's stacked IPv6
  // addresses field).
  function parseBody(body) {
    const lines = (body || "").split("\n");
    let i = 0;
    const meta = {};
    while (i < lines.length) {
      const line = lines[i];
      if (line.trim() === "") { i += 1; continue; }
      const tabIdx = line.indexOf("\t");
      const key = (tabIdx === -1 ? line : line.slice(0, tabIdx)).trim();
      const rest = tabIdx === -1 ? "" : line.slice(tabIdx + 1);
      if (META_KEYS.includes(key)) {
        meta[key] = rest.trim();
        i += 1;
        if (key === "Scheduled By") { i += 1; break; }
      } else {
        break;
      }
    }

    let displayed = null, total = null, noData = false;
    let header = [], rows = [];

    if (i < lines.length) {
      const summaryLine = lines[i].trim();
      if (summaryLine.startsWith("No data")) {
        noData = true;
        i += 1;
      } else {
        const m = summaryLine.match(/Displaying (\d+) out of ([\d,]+)/);
        if (m) {
          displayed = parseInt(m[1], 10);
          total = parseInt(m[2].replace(/,/g, ""), 10);
        }
        i += 1;
        if (i < lines.length) {
          header = splitLine(lines[i]);
          i += 1;
          let expectedIdx = 1;
          let bufferLines = [];

          const flush = () => {
            if (!bufferLines.length) return;
            const joined = bufferLines.join("\n");
            let row = joined.split("\t").map((c) => c.trim());
            while (row.length && row[row.length - 1] === "") row.pop();
            if (row.length) rows.push(row);
            bufferLines = [];
          };

          while (i < lines.length) {
            const line = lines[i];
            if (line.trim() === "" && !bufferLines.length) { i += 1; continue; }
            if (line.trim() === "") { i += 1; continue; }
            const m2 = line.match(/^(\d+)\s*\t/);
            if (m2 && parseInt(m2[1], 10) === expectedIdx) {
              flush();
              bufferLines = [line];
              expectedIdx += 1;
            } else if (bufferLines.length) {
              bufferLines.push(line);
            }
            i += 1;
          }
          flush();
        }
      }
    }

    return { meta, no_data: noData, displayed, total, header, rows };
  }

  function parseTimeRange(v) {
    const m = (v || "").match(/(.+?) to (.+)/);
    if (!m) return [v || "", ""];
    return [m[1].trim(), m[2].trim()];
  }

  // Parses one uploaded CSV's raw text (Outlook export: Subject, Body, ...)
  // into a list of "email" objects, same shape as parse_both.py's parse_file().
  function parseCsvText(text, fileLabel) {
    // Delimiter must be forced to a comma. PapaParse's delimiter
    // auto-detection samples the first ~1MB of text and picks whichever
    // candidate delimiter (comma, tab, pipe, semicolon) looks most
    // consistent; because the Body column is full of tab-separated data,
    // auto-detect can pick tab as the outer delimiter and silently mangle
    // the two-column Subject,Body structure. This is a real Outlook CSV
    // export, always comma-delimited at the outer level, so pin it.
    const result = Papa.parse(text, { skipEmptyLines: false, delimiter: "," });
    const rows = result.data;
    const emails = [];
    // rows[0] is the header row, mirrors csv.reader + next(r) in Python.
    for (let idx = 1; idx < rows.length; idx++) {
      const row = rows[idx];
      if (!row || row.length === 0) continue;
      const subject = (row[0] || "");
      if (subject.trim() === "Welcome to Sumo Logic!") continue;
      if (subject.trim() === "" && (!row[1] || row[1].trim() === "")) continue;
      const body = row[1] || "";
      const p = parseBody(body);
      p.subject = subject;
      p.file = fileLabel;
      emails.push(p);
    }
    return emails;
  }

  global.SocParse = { parseBody, splitLine, parseTimeRange, parseCsvText, META_KEYS };
})(window);
