# Security and data handling

This tool runs entirely inside your own browser tab. Nothing about using it
sends your CSV data, or anything derived from it, anywhere else.

## What "client-side only" means here

When you open this page (whether from GitHub Pages or a local file), your
browser downloads the HTML, CSS, and JavaScript that make up the app. From
that point on:

- You select CSV files with the file picker or by dragging them onto the
  page. This uses the browser's local File API (`FileReader`). The browser
  reads the file from your disk directly into memory in that tab; the file
  never touches a server.
- All parsing, entity extraction, classification, and Excel workbook
  generation happen in JavaScript running in that same browser tab, using
  data that already exists only in that tab's memory.
- The finished .xlsx file is built in memory (as a `Blob`) and offered to you
  as a normal browser download via an object URL
  (`URL.createObjectURL(blob)`). That download never goes anywhere except
  your own downloads folder.
- The two third-party libraries this app uses, PapaParse (CSV parsing) and
  ExcelJS (Excel file generation), are vendored into `js/lib/` in this
  repository and loaded from the same origin as the page. They are not
  fetched from a CDN at runtime, and neither library makes any network calls
  on its own; they are pure in-memory data transformation libraries.

## GitHub Pages is public, your data is not

GitHub Pages serves the app's own source files (HTML, CSS, JS) at a public
URL, the same way any static website is public. That is expected and fine:
the page itself contains no data of yours, since it is only code. Nothing
about a visitor loading the page transmits any CSV file, because the code
does not read any file until you explicitly choose one in your own browser,
and reading it never leaves that browser. Visiting the URL and using the
tool does not expose your data to anyone, including the app's author, GitHub,
or any other visitor.

## How to verify this yourself, instead of taking it on faith

The entire app is plain, unminified JavaScript in this repository (except
the two vendored libraries in `js/lib/`, which are unmodified upstream
releases of PapaParse and ExcelJS). You do not need to trust this document;
you can check it directly:

1. Search the repository for any network call:
   `grep -rn "fetch(\|XMLHttpRequest\|WebSocket\|navigator.sendBeacon" js/ index.html`
   This should return no matches outside `js/lib/` (the vendored libraries
   themselves do not call these either, since they are pure parsing and
   file-writing libraries with no network functionality).
2. Open your browser's developer tools, go to the Network tab, clear it, and
   then upload a CSV and generate a workbook. You should see zero outgoing
   requests the entire time, other than the initial page load of the app's
   own static files.
3. Disconnect from the internet entirely after the page has loaded once, and
   confirm the tool still works fully offline. If it needed to send your
   data anywhere, it would fail without a network connection; it does not.

## Scope of this guarantee

This document describes the data handling of this application's own code.
It does not, and cannot, make claims about your browser, your operating
system, or any browser extension you have installed; those are outside this
project's control. It also does not cover what you choose to do with the
downloaded .xlsx file afterward, such as uploading it somewhere yourself.
