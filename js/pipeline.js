// pipeline.js
// Orchestrates: multi-file parsing merge, pairwise timestamp overlap
// detection per alert type, entity-level grouping (Tier 1 known extractors
// or Tier 2 generic fallback), classification, master/network/host row
// construction, and the mandatory reconciliation check. Nothing in this
// file performs network I/O; everything operates on in-memory data derived
// from files the user selected locally.

(function (global) {
  "use strict";

  const { parseCsvText, parseTimeRange } = SocParse;
  const { EXTRACTORS, ex_generic_fallback, toInt } = SocExtractors;
  const { CLASSIFIERS, cls_generic_fallback } = SocClassify;
  const { LEVEL_BY_ALERT, ZERO_COUNT_ALERTS } = SocMatrixData;

  const UNCLASSIFIED_LEVEL = "Unclassified, review required";

  // ---------------- Step 1: parse all uploaded files ----------------
  // files: [{ name, text }]. Returns { emailsByFile: Map(name -> emails[]),
  // allEmails: [] } where each email also carries a "file" label.
  function parseAllFiles(files) {
    const emailsByFile = new Map();
    const allEmails = [];
    for (const f of files) {
      const emails = parseCsvText(f.text, f.name);
      emailsByFile.set(f.name, emails);
      allEmails.push(...emails);
    }
    return { emailsByFile, allEmails };
  }

  // ---------------- Step 2: pairwise timestamp overlap detection ----------------
  // For every alert type (subject) present in more than one uploaded file,
  // check every pair of files that contain that subject for an overlapping
  // Time Range window. Returns a list of conflicts:
  // { subject, fileA, fileB, windowA, windowB }
  // Native Date.parse() is implementation-defined for anything that is not
  // ISO-8601 and is unreliable across browsers for Sumo Logic's timestamp
  // formats (which commonly include a trailing timezone abbreviation like
  // "EDT" that Date.parse cannot handle, or a "MM/DD/YYYY hh:mm:ss AM" US
  // format). Try, in order: as-is, with a trailing alphabetic timezone
  // abbreviation stripped, and with common separators normalized. Only
  // fall back to "unparseable" (treated conservatively as a possible
  // overlap) if none of these succeed.
  function tryParseDate(s) {
    if (!s) return null;
    const raw = s.trim();
    const attempts = [raw];
    // Strip a trailing timezone abbreviation, e.g. "... 05:00:00 PM EDT"
    // or "...T17:00:00 UTC" -> "... 05:00:00 PM" / "...T17:00:00".
    const tzStripped = raw.replace(/\s+[A-Z]{2,5}$/, "");
    if (tzStripped !== raw) attempts.push(tzStripped);
    // Normalize "YYYY-MM-DD HH:MM:SS" (space separator, no timezone) to
    // ISO with a "T", which every engine parses consistently.
    const isoLike = tzStripped.match(/^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})$/);
    if (isoLike) attempts.push(`${isoLike[1]}T${isoLike[2]}`);
    for (const a of attempts) {
      const t = Date.parse(a);
      if (!isNaN(t)) return t;
    }
    return null;
  }

  function collectWindows(emails, subject) {
    const windows = [];
    for (const e of emails) {
      if (e.subject !== subject) continue;
      const tr = e.meta && e.meta["Time Range"];
      if (!tr) continue;
      const [startStr, endStr] = parseTimeRange(tr);
      const start = tryParseDate(startStr);
      const end = tryParseDate(endStr);
      windows.push({ start, end, startStr, endStr, raw: tr });
    }
    return windows;
  }

  function windowsOverlap(a, b) {
    // If either side failed to parse as a real date, be conservative and
    // treat it as a potential overlap so a human reviews it explicitly.
    if (a.start === null || a.end === null || b.start === null || b.end === null) return true;
    return a.start <= b.end && b.start <= a.end;
  }

  function detectOverlaps(emailsByFile) {
    const fileNames = Array.from(emailsByFile.keys());
    const subjectsByFile = new Map();
    for (const [name, emails] of emailsByFile) {
      subjectsByFile.set(name, new Set(emails.map((e) => e.subject)));
    }
    const allSubjects = new Set();
    for (const s of subjectsByFile.values()) for (const subj of s) allSubjects.add(subj);

    const conflicts = [];
    for (const subject of allSubjects) {
      const filesWithSubject = fileNames.filter((n) => subjectsByFile.get(n).has(subject));
      if (filesWithSubject.length < 2) continue;
      for (let i = 0; i < filesWithSubject.length; i++) {
        for (let j = i + 1; j < filesWithSubject.length; j++) {
          const fa = filesWithSubject[i], fb = filesWithSubject[j];
          const wa = collectWindows(emailsByFile.get(fa), subject);
          const wb = collectWindows(emailsByFile.get(fb), subject);
          for (const a of wa) {
            for (const b of wb) {
              if (windowsOverlap(a, b)) {
                conflicts.push({
                  subject, fileA: fa, fileB: fb,
                  windowA: a.raw || `${a.startStr} to ${a.endStr}`,
                  windowB: b.raw || `${b.startStr} to ${b.endStr}`,
                });
              }
            }
          }
        }
      }
    }
    return conflicts;
  }

  // ---------------- Step 3: entity grouping (per subject) ----------------
  // resolutions: Map("subject|fileA|fileB" -> "both"|"excludeA"|"excludeB")
  // used to decide which files' data is included for a conflicted subject.
  function filesExcludedForSubject(subject, conflicts, resolutions) {
    const excluded = new Set();
    for (const c of conflicts) {
      if (c.subject !== subject) continue;
      const key = `${c.subject}|${c.fileA}|${c.fileB}`;
      const res = resolutions.get(key);
      if (res === "excludeA") excluded.add(c.fileA);
      else if (res === "excludeB") excluded.add(c.fileB);
      // "both" (merge anyway) or unresolved: no exclusion (unresolved is
      // blocked earlier at the UI level before generation is allowed).
    }
    return excluded;
  }

  function groupSubject(subject, emailsByFile, conflicts, resolutions, isKnown) {
    const excluded = filesExcludedForSubject(subject, conflicts, resolutions);
    const extractor = isKnown ? EXTRACTORS[subject] : ex_generic_fallback;
    const groups = new Map(); // stringified key -> { key, disp, count, runs, ctxSamples }

    for (const [fileName, emails] of emailsByFile) {
      if (excluded.has(fileName)) continue;
      for (const e of emails) {
        if (e.subject !== subject || e.no_data) continue;
        const header = e.header.filter((x) => x !== "#");
        const hl = header.map((x) => x.toLowerCase());
        const countIdx = hl.indexOf("count") !== -1 ? hl.indexOf("count")
          : (hl.indexOf("eventcount") !== -1 ? hl.indexOf("eventcount") : -1);
        const runAt = (e.meta && e.meta["Run At"]) || "";

        for (const row of e.rows) {
          let data = row.slice(1, 1 + header.length);
          if (data.length < header.length) {
            data = data.concat(new Array(header.length - data.length).fill(""));
          }
          let n = 1;
          if (countIdx !== -1) {
            const parsed = toInt(data[countIdx]);
            n = parsed !== null ? parsed : 1;
          }
          const { key, disp, ctx } = extractor(header, hl, data, runAt);
          const keyStr = JSON.stringify(key);
          if (!groups.has(keyStr)) {
            groups.set(keyStr, { key, disp, count: 0, runs: [], ctxSamples: [] });
          }
          const g = groups.get(keyStr);
          g.count += n;
          g.runs.push(runAt);
          if (g.ctxSamples.length < 5) g.ctxSamples.push(ctx);
        }
      }
    }
    return groups;
  }

  // ---------------- Step 4: build granular (entity level) rows ----------------
  function buildGranularRows(emailsByFile, conflicts, resolutions, onProgress) {
    const allSubjects = new Set();
    for (const emails of emailsByFile.values()) for (const e of emails) allSubjects.add(e.subject);

    const rows = [];
    let processed = 0;
    for (const subject of allSubjects) {
      const isKnown = Object.prototype.hasOwnProperty.call(EXTRACTORS, subject);
      const groups = groupSubject(subject, emailsByFile, conflicts, resolutions, isKnown);
      const level = isKnown ? (LEVEL_BY_ALERT[subject] || "Medium") : UNCLASSIFIED_LEVEL;
      const classifier = isKnown ? CLASSIFIERS[subject] : null;

      for (const g of groups.values()) {
        const ctx = g.ctxSamples[0] || {};
        let classification, explanation;
        if (isKnown && classifier) {
          [classification, explanation] = classifier(ctx);
        } else {
          [classification, explanation] = cls_generic_fallback(ctx, subject);
        }
        const timestamps = g.runs.filter((t) => t);
        let tsTxt = "";
        if (timestamps.length && timestamps.length <= 3) tsTxt = timestamps.join("; ");
        else if (timestamps.length > 3) tsTxt = `${timestamps[0]} through ${timestamps[timestamps.length - 1]} (${g.runs.length} occurrences)`;
        const fullAlert = `${subject}: ${g.disp}` + (tsTxt ? ` [${tsTxt}]` : "");
        rows.push({
          alert: fullAlert, level, count: g.count, classification, explanation,
          subject, isKnown, tokens: ctx.tokens || null,
        });
      }
      processed += 1;
      if (onProgress) onProgress(processed, allSubjects.size);
    }

    // Zero-count known alert types not present at all in this batch of files.
    const presentSubjects = allSubjects;
    for (const z of ZERO_COUNT_ALERTS) {
      if (presentSubjects.has(z.alert)) continue;
      rows.push({
        alert: `${z.alert}: No specific IP, host, or entity data available (zero occurrences this period)`,
        level: z.level, count: 0, classification: "N/A (No Occurrences This Period)",
        explanation: z.zero_explanation, subject: z.alert, isKnown: true, tokens: null,
      });
    }
    return rows;
  }

  // ---------------- Step 5: categorize into Network / Host ----------------
  function categorize(row) {
    const text = row.subject || row.alert;
    if (/Palo Alto|Fortinet/.test(text)) return "Network";
    if (/Cortex XDR|Windows/.test(text)) return "Host";
    // Tier 2 generic fallback: use whichever token type predominates.
    const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
    if (row.tokens && row.tokens.some((t) => IPV4_RE.test(t) || t.includes(":"))) return "Network";
    return "Host";
  }

  // ---------------- Step 6: master (per-alert-type rollup) rows ----------------
  function buildMasterRows(granularRows) {
    const bySubject = new Map();
    for (const r of granularRows) {
      if (!bySubject.has(r.subject)) bySubject.set(r.subject, []);
      bySubject.get(r.subject).push(r);
    }
    const masterRows = [];
    for (const [subject, rows] of bySubject) {
      const level = rows[0].level;
      const total = rows.reduce((s, r) => s + r.count, 0);

      // Zero-occurrence placeholder passthrough.
      if (rows.length === 1 && rows[0].classification === "N/A (No Occurrences This Period)") {
        masterRows.push({
          alert: subject, level, count: 0,
          classification: "N/A (No Occurrences This Period)",
          explanation: rows[0].explanation,
        });
        continue;
      }

      const byClass = new Map();
      for (const r of rows) byClass.set(r.classification, (byClass.get(r.classification) || 0) + r.count);
      const sortedClasses = Array.from(byClass.entries()).sort((a, b) => b[1] - a[1]);
      const majorityClass = sortedClasses[0][0];
      const classification = sortedClasses.length > 1
        ? `${majorityClass} (Mixed, see entity detail tabs)`
        : majorityClass;

      const breakdown = sortedClasses.map(([c, n]) => `${n.toLocaleString()} ${c}`).join(", ");
      const explanation =
        `This alert type produced ${rows.length.toLocaleString()} distinct entity level row(s) in the ` +
        `Network Activity or Host Activity tab, totaling ${total.toLocaleString()} occurrences. ` +
        `Classification breakdown by occurrence count: ${breakdown}. See the entity detail tab for the ` +
        `specific hosts, IPs, accounts, or files involved and the per-entity classification and reasoning.`;

      masterRows.push({ alert: subject, level, count: total, classification, explanation });
    }
    return masterRows;
  }

  // ---------------- Step 7: em dash validation ----------------
  function findEmDashes(rows, fieldsPerRow) {
    const bad = [];
    for (const r of rows) {
      for (const f of fieldsPerRow) {
        const v = r[f];
        if (typeof v === "string" && v.includes("\u2014")) bad.push({ row: r, field: f });
      }
    }
    return bad;
  }

  // ---------------- Step 8: mandatory reconciliation check ----------------
  function reconcile(masterRows, netRows, hostRows, granularRows) {
    const masterTotal = masterRows.reduce((s, r) => s + r.count, 0);
    const netTotal = netRows.reduce((s, r) => s + r.count, 0);
    const hostTotal = hostRows.reduce((s, r) => s + r.count, 0);
    const grandTotal = granularRows.reduce((s, r) => s + r.count, 0);
    const countsOk = netTotal + hostTotal === grandTotal;
    const rowsOk = netRows.length + hostRows.length === granularRows.length;
    const masterMatchesGrand = masterTotal === grandTotal;
    return {
      masterTotal, netTotal, hostTotal, grandTotal,
      ok: countsOk && rowsOk && masterMatchesGrand,
      countsOk, rowsOk, masterMatchesGrand,
    };
  }

  global.SocPipeline = {
    parseAllFiles, detectOverlaps, buildGranularRows, buildMasterRows,
    categorize, findEmDashes, reconcile, UNCLASSIFIED_LEVEL,
  };
})(window);
