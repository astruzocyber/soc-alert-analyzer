/* app.js
 * UI orchestration only. Reads files with FileReader, drives the pipeline
 * modules, renders the overlap-conflict resolution UI and the mandatory
 * reconciliation banner, and triggers the in-memory Blob download.
 *
 * IMPORTANT: This file, like every other file in this repository, contains
 * no fetch(), no XMLHttpRequest, no WebSocket, and no analytics or telemetry
 * call of any kind. Grep the repo for "fetch(" or "XMLHttpRequest" to verify
 * this yourself; see SECURITY.md for the full data handling explanation.
 */

(function () {
  "use strict";

  const dropZone = document.getElementById("drop-zone");
  const fileInput = document.getElementById("file-input");
  const fileListEl = document.getElementById("file-list");
  const processBtn = document.getElementById("process-btn");
  const progressWrap = document.getElementById("progress-wrap");
  const progressBar = document.getElementById("progress-bar");
  const progressLabel = document.getElementById("progress-label");
  const conflictsEl = document.getElementById("conflicts");
  const reconEl = document.getElementById("reconciliation");
  const errorBanner = document.getElementById("error-banner");
  const downloadBtn = document.getElementById("download-btn");
  const statsEl = document.getElementById("stats");

  let selectedFiles = []; // [{ name, text }]
  let lastResult = null;  // computed pipeline output, kept for the download step
  let resolutions = new Map(); // "subject|fileA|fileB" -> "both"|"excludeA"|"excludeB"

  function readFileAsText(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(reader.error);
      reader.readAsText(file);
    });
  }

  function renderFileList() {
    fileListEl.innerHTML = "";
    for (const f of selectedFiles) {
      const li = document.createElement("li");
      li.textContent = `${f.name} (${(f.text.length / 1024).toFixed(1)} KB)`;
      fileListEl.appendChild(li);
    }
    processBtn.disabled = selectedFiles.length === 0;
  }

  async function addFiles(fileListLike) {
    const incoming = Array.from(fileListLike).filter((f) => /\.csv$/i.test(f.name));
    for (const f of incoming) {
      const text = await readFileAsText(f);
      // Files never leave the browser: this is the only place file content
      // is read, and it is only ever stored in local JS variables / passed
      // to the in-page parser below.
      selectedFiles.push({ name: f.name, text });
    }
    renderFileList();
  }

  dropZone.addEventListener("dragover", (e) => { e.preventDefault(); dropZone.classList.add("drag"); });
  dropZone.addEventListener("dragleave", () => dropZone.classList.remove("drag"));
  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("drag");
    if (e.dataTransfer && e.dataTransfer.files) addFiles(e.dataTransfer.files);
  });
  dropZone.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", () => { if (fileInput.files.length) addFiles(fileInput.files); });

  function resetOutputUI() {
    conflictsEl.innerHTML = "";
    conflictsEl.classList.add("hidden");
    reconEl.innerHTML = "";
    reconEl.classList.add("hidden");
    errorBanner.classList.add("hidden");
    errorBanner.textContent = "";
    downloadBtn.disabled = true;
    statsEl.innerHTML = "";
    progressWrap.classList.add("hidden");
  }

  function showError(msg) {
    errorBanner.textContent = msg;
    errorBanner.classList.remove("hidden");
  }

  function conflictKey(c) { return `${c.subject}|${c.fileA}|${c.fileB}`; }

  function renderConflicts(conflicts) {
    if (!conflicts.length) { conflictsEl.classList.add("hidden"); return; }
    conflictsEl.classList.remove("hidden");
    conflictsEl.innerHTML = "<h3>Timestamp overlap conflicts: choose how to handle each pair</h3>" +
      "<p>These file pairs report the same alert type over an overlapping time window. Merging them " +
      "automatically would double count events. Pick a resolution for each pair below; the workbook " +
      "will be built automatically once every conflict has a resolution selected.</p>";
    const list = document.createElement("div");
    for (const c of conflicts) {
      const key = conflictKey(c);
      const box = document.createElement("div");
      box.className = "conflict-item";
      box.innerHTML = `
        <div class="conflict-title">${escapeHtml(c.subject)}</div>
        <div>File A: <strong>${escapeHtml(c.fileA)}</strong> window: ${escapeHtml(c.windowA)}</div>
        <div>File B: <strong>${escapeHtml(c.fileB)}</strong> window: ${escapeHtml(c.windowB)}</div>
      `;
      const select = document.createElement("select");
      select.innerHTML = `
        <option value="">Choose a resolution...</option>
        <option value="excludeB">Use only ${escapeHtml(c.fileA)} for this alert type</option>
        <option value="excludeA">Use only ${escapeHtml(c.fileB)} for this alert type</option>
        <option value="both">Merge anyway (I have confirmed these do not actually double count)</option>
      `;
      select.value = resolutions.get(key) || "";
      select.addEventListener("change", () => {
        if (select.value) resolutions.set(key, select.value);
        else resolutions.delete(key);
        const allResolved = conflicts.every((c) => resolutions.has(conflictKey(c)));
        if (!allResolved) {
          downloadBtn.disabled = true;
          showError("Resolve every timestamp overlap conflict above before generating the workbook.");
          return;
        }
        errorBanner.classList.add("hidden");
        // Every conflict now has a resolution: automatically re-run the
        // pipeline with those resolutions applied. This is only triggered
        // here, from direct user interaction with a resolution dropdown,
        // never from renderConflicts' own internal bookkeeping call below,
        // so a re-render of an already-resolved conflict list can never
        // recursively trigger another run.
        runPipeline().catch((err) => {
          showError(`Processing error: ${err.message}`);
          console.error(err);
        });
      });
      box.appendChild(select);
      list.appendChild(box);
    }
    conflictsEl.appendChild(list);
    updateProcessAvailability(conflicts);
  }

  function updateProcessAvailability(conflicts) {
    const allResolved = conflicts.every((c) => resolutions.has(conflictKey(c)));
    downloadBtn.disabled = !allResolved;
    if (!allResolved) {
      showError("Resolve every timestamp overlap conflict above before generating the workbook.");
    } else {
      errorBanner.classList.add("hidden");
    }
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  function setProgress(label, current, total) {
    progressWrap.classList.remove("hidden");
    progressLabel.textContent = label;
    const pct = total ? Math.round((current / total) * 100) : 0;
    progressBar.style.width = `${pct}%`;
  }

  processBtn.addEventListener("click", async () => {
    resetOutputUI();
    processBtn.disabled = true;
    try {
      await runPipeline();
    } catch (err) {
      showError(`Processing error: ${err.message}`);
      console.error(err);
    } finally {
      processBtn.disabled = false;
    }
  });

  async function runPipeline() {
    setProgress("Parsing uploaded CSV files", 0, 1);
    await nextFrame();
    const { emailsByFile, allEmails } = SocPipeline.parseAllFiles(selectedFiles);

    setProgress("Checking for timestamp overlaps between files", 0, 1);
    await nextFrame();
    const conflicts = SocPipeline.detectOverlaps(emailsByFile);
    renderConflicts(conflicts);
    if (conflicts.length && !conflicts.every((c) => resolutions.has(conflictKey(c)))) {
      progressWrap.classList.add("hidden");
      return; // wait for the user to resolve conflicts, then re-run
    }

    const totalSubjects = new Set(allEmails.map((e) => e.subject)).size;
    setProgress("Grouping entities and running classification", 0, totalSubjects);
    const granularRows = SocPipeline.buildGranularRows(emailsByFile, conflicts, resolutions,
      (done, total) => setProgress("Grouping entities and running classification", done, total));
    await nextFrame();

    const masterRows = SocPipeline.buildMasterRows(granularRows);
    const netRows = granularRows.filter((r) => SocPipeline.categorize(r) === "Network");
    const hostRows = granularRows.filter((r) => SocPipeline.categorize(r) === "Host");

    const emDashHits = SocPipeline.findEmDashes(
      [...masterRows, ...netRows, ...hostRows],
      ["alert", "level", "classification", "explanation"]
    );
    if (emDashHits.length) {
      showError(`Blocked: ${emDashHits.length} generated field(s) contain an em dash (U+2014). ` +
        `Download disabled until this is fixed in the source templates.`);
      progressWrap.classList.add("hidden");
      return;
    }

    const recon = SocPipeline.reconcile(masterRows, netRows, hostRows, granularRows);
    renderReconciliation(recon);
    if (!recon.ok) {
      showError("Reconciliation check failed: Network Activity plus Host Activity does not exactly equal " +
        "the master matrix total, or a row is not categorized into exactly one detail tab. Download is " +
        "disabled. This mirrors the assertion the Python pipeline performs before saving.");
      progressWrap.classList.add("hidden");
      return;
    }

    const knownCount = granularRows.filter((r) => r.isKnown).length;
    const fallbackCount = granularRows.filter((r) => !r.isKnown).length;
    statsEl.innerHTML = `
      <ul>
        <li>Files processed: ${selectedFiles.length}</li>
        <li>Total raw table rows across all files: ${allEmails.reduce((s, e) => s + (e.rows ? e.rows.length : 0), 0).toLocaleString()}</li>
        <li>Distinct alert types seen: ${totalSubjects}</li>
        <li>Entity level rows: ${granularRows.length.toLocaleString()} (${knownCount.toLocaleString()} known type, ${fallbackCount.toLocaleString()} generic fallback)</li>
      </ul>`;

    lastResult = {
      masterRows, netRows, hostRows, granularRows, recon,
      meta: {
        fileNames: selectedFiles.map((f) => f.name),
        subjectCount: totalSubjects,
        knownCount, fallbackCount, reconcile: recon,
        conflictSummary: conflicts.length
          ? `  ${conflicts.length} overlap conflict(s) were detected and resolved by the user before generation.`
          : "  No overlapping alert types were found across the uploaded files.",
      },
    };

    downloadBtn.disabled = false;
    progressWrap.classList.add("hidden");
  }

  function renderReconciliation(recon) {
    reconEl.classList.remove("hidden");
    reconEl.className = recon.ok ? "recon ok" : "recon fail";
    reconEl.innerHTML = `
      <h3>Reconciliation check</h3>
      <div>Master matrix total: <strong>${recon.masterTotal.toLocaleString()}</strong></div>
      <div>Network Activity total: <strong>${recon.netTotal.toLocaleString()}</strong></div>
      <div>Host Activity total: <strong>${recon.hostTotal.toLocaleString()}</strong></div>
      <div>Network + Host: <strong>${(recon.netTotal + recon.hostTotal).toLocaleString()}</strong></div>
      <div>Status: <strong>${recon.ok ? "PASS: totals match exactly" : "FAIL: see error banner"}</strong></div>
    `;
  }

  downloadBtn.addEventListener("click", async () => {
    if (!lastResult) return;
    downloadBtn.disabled = true;
    try {
      const rowCount = lastResult.masterRows.length + lastResult.netRows.length + lastResult.hostRows.length;
      const showXlsxProgress = rowCount >= 50000;
      if (showXlsxProgress) progressWrap.classList.remove("hidden");
      const blob = await SocXlsx.buildWorkbook(
        { masterRows: lastResult.masterRows, netRows: lastResult.netRows, hostRows: lastResult.hostRows },
        lastResult.meta,
        showXlsxProgress ? (label, cur, tot) => setProgress(label, cur, tot) : null
      );
      // In-memory Blob offered as a direct browser download via an object
      // URL. Nothing here transmits the blob anywhere; the URL is local to
      // this browser tab and is revoked immediately after the click.
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      const stamp = new Date().toISOString().slice(0, 10);
      a.href = url;
      a.download = `SOC_Alert_Analysis_${stamp}.xlsx`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
      progressWrap.classList.add("hidden");
    } catch (err) {
      showError(`Workbook generation error: ${err.message}`);
      console.error(err);
    } finally {
      downloadBtn.disabled = false;
    }
  });

  function nextFrame() { return new Promise((r) => requestAnimationFrame(() => setTimeout(r, 0))); }
})();
