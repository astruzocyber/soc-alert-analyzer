# SOC Alert Analyzer (client-side)

A zero-cost, fully static, browser-only web app that turns one or more
Outlook-exported Sumo Logic alert email CSVs into a formatted SOC Alert
Analysis Matrix workbook (.xlsx). It is a direct JavaScript port of an
existing Python pipeline, redesigned to run entirely in the browser so the
source data never leaves your machine. See `SECURITY.md` for the full data
handling model.

## How to use it

1. Open `index.html` (locally, or the GitHub Pages URL this repo is deployed
   to). No installation, build step, or server is required.
2. Drag and drop one or more Sumo Logic export CSV files onto the drop zone,
   or click it to choose files with the file picker. Any number of files is
   supported, not just one or two.
3. Click "Process files". The app parses every file, groups rows into
   entities per alert type, classifies known alert types, and runs a
   pairwise timestamp overlap check across every pair of uploaded files that
   share an alert type.
4. If any overlap conflicts are found, resolve each one using the dropdown
   shown (use only one file's data for that alert type, or confirm merging
   is safe). Processing re-runs automatically once every conflict is
   resolved.
5. Once the reconciliation check passes (see below) and no em dashes were
   found in the generated text, the "Download .xlsx workbook" button
   enables. Click it to save the workbook directly from your browser.

## What the workbook contains

Four tabs, matching the original Python pipeline's structure:

- **Alert Analysis Matrix**: one row per alert type (rule), with Count
  summed across every occurrence in every uploaded file, a static Critical
  Level, and a rollup Classification with a breakdown explanation.
- **Network Activity**: one row per unique entity combination (for example
  internal host, external IP, and port) for network-oriented alert types.
- **Host Activity**: one row per unique entity combination (for example host
  name, file path, or user account) for host-oriented alert types.
- **Methodology & Notes**: the reconciliation math, file list, and a plain
  language explanation of the fallback and multi-file logic used to build
  the other three tabs.

Every data row has exactly five columns: Full Alert, Critical Level, Count,
Classification, Explanation. Critical Level and Classification are
color-filled; the Explanation column is wrapped; the header row is frozen
with autofilter enabled; and the last row in each of the first three tabs is
a TOTAL row using a real `=SUM()` formula over the Count column, so it
recalculates correctly if you edit rows in Excel afterward.

## Alert types with purpose-built parsing and classification

The following exact Subject strings have a dedicated extractor (entity
grouping key) and classifier (True/False Positive reasoning), ported
directly from the reference Python pipeline's `extract_entities.py` and
`classify.py`:

- GFR Media - WARNING - Palo Alto - Accepted Malicious Connections Out
- GFR Media - WARNING - Palo Alto - Accepted Malicious Connections In
- Search Results: GFR Media - Daily Report - Palo Alto - Blocked Viruses & Spyware Report
- GFR Media - WARNING - Palo Alto - Viruses & Spyware Alert
- GFR Media - Daily Report - Palo Alto - Viruses & Spyware Report
- GFR Media - WARNING - Palo Alto - High Data Transfer Usage
- GFR Media - Critical Alert - Successful User Logins to Firewall (Palo Alto)
- GFR Media / LinkActiv - Critical Alert - Fortinet - Successful User Login - Off Hours (and "Off hours")
- GFR Media / LinkActiv - Daily Report - Fortinet - Admin Login Disabled (Account Locked Out)
- GFR Media / LinkActiv - Daily Report - Fortinet - Successful User Login
- GFR Media - Daily Report - Cortex XDR - Malware Detected
- GFR Media - Critical Alert - Cortex XDR - Malware Detected
- GFR Media - Windows Failed Logins (Daily Report)
- GFR Media/LinkActiv - Daily Report - Windows - Admin Attempts by User
- GFR Media/LinkActiv - Daily Report - Windows - Failed Login Attempts
- GFR Media/LinkActiv - Daily Report - Windows - Successful Login
- GFR Media/LinkActiv - Daily Report - Windows - System Time Change
- GFR Media/LinkActiv - Daily Report - Windows - User Account Created (and "- Off Hours" / "- Prohibited system")
- GFR Media/LinkActiv - Daily Report - Windows - User Account Locked
- GFR Media/LinkActiv - Daily Report - Windows - User Account Password Changes
- GFR Media/LinkActiv - Daily Report - Windows - User Login from Multiple Hosts

Every other alert type listed in `matrix_data.py`'s static severity table
(for example the various Fortinet group/user management alerts) has a
Critical Level entry and, if it produces zero rows in a given period, an
explanatory placeholder row in the Alert Analysis Matrix tab, matching the
Python pipeline's behavior for rules with no data that period.

## How the generic fallback behaves for anything else

Any Subject string not in the list above (a genuinely new or unexpected
alert type) is still processed, never dropped or crashed on. It goes through
a schema-agnostic Tier 2 path:

- Every field value in each row is scanned with regular expressions for
  IPv4-shaped and hostname-shaped tokens.
- Rows are grouped into one entity row per distinct set of tokens found in
  that row.
- Any field literally named `Count` or `eventcount` (case-insensitive) is
  still summed into that row's Count, exactly like the known alert types.
  This detection is done by field name, universally, not by alert type.
- Critical Level is set to "Unclassified, review required".
- Classification is set to "Needs Manual Classification" (never a guessed
  True/False Positive).
- The Explanation column states plainly that this alert type has no
  purpose-built rule yet, names the tokens that were grouped on, and
  includes a short sample of the row's raw field values so a reviewer can
  see what they are working with.
- These rows get their own distinct fill color in the workbook (separate
  from every True/False Positive fill) so they are easy to find and triage
  first.

## Graduating an alert type from the fallback to a proper extractor

Once you have looked at a handful of raw rows for a new alert type (the
"Sample raw field values" text in its Explanation column is a good starting
point) and understand its actual columns, add purpose-built handling for it
in three places, mirroring exactly how a new alert type is added to the
Python pipeline today:

1. **`js/matrix_data.js`**: add an entry to the `ROWS` array with the exact
   Subject string and its Critical Level (a fixed severity rating,
   independent of whether occurrences this period look like true or false
   positives). Optionally add a `zero_explanation` string used when the
   alert type produces no rows in a given period.

2. **`js/extractors.js`**: write a new extractor function
   `function ex_my_new_alert(header, headerLower, data) { ... }` that reads
   the specific field names for this alert type (use the `get(headerLower,
   data, "field name")` helper, matching column names case-insensitively)
   and returns `{ key: [...], disp: "...", ctx: {...} }`:
   - `key`: the array of field values that defines "the same entity" for
     this alert type (for example `[host, externalIp, port]`). Rows with
     the same key are merged into one output row with Count summed.
   - `disp`: a short human-readable description of the entity, used to
     build the Full Alert text.
   - `ctx`: whatever fields the classifier (next step) needs to make its
     decision.
   Then add `"Exact Subject String": ex_my_new_alert,` to the `EXTRACTORS`
   map at the bottom of the file.

3. **`js/classify.js`**: write a new classifier function
   `function cls_my_new_alert(ctx) { ... }` that returns
   `[classification, explanation]`, where `classification` is one of
   `"True Positive"`, `"True Positive (Likely)"`, `"True Positive (Blocked)"`,
   `"False Positive (Likely)"`, or another short label consistent with the
   existing ones, and `explanation` is a plain-language paragraph with no em
   dashes (use commas, colons, or parentheses instead of "-", the U+2014
   character). Then add `"Exact Subject String": cls_my_new_alert,` to the
   `CLASSIFIERS` map at the bottom of the file.

Once all three are in place, that Subject string is automatically pulled out
of the Tier 2 fallback path and into Tier 1 the next time you process files
containing it; no other code changes are needed. Reload the page (no build
step) and verify with a sample file that the new alert type now appears with
real classification instead of "Needs Manual Classification".

## Row volume and performance

Parsing, grouping, and classification stay responsive into the tens of
thousands of rows. Generating the heavily styled .xlsx (per-cell fills,
wrapped text, computed row heights) can slow down noticeably well beyond
that; this is an accepted trade-off of doing the formatting entirely in the
browser rather than on a server, and the app shows a progress indicator
during workbook generation once the combined row count crosses 50,000
rather than truncating any data or leaving the tab looking frozen.

## Multi-file support

Unlike the original two-file Python pipeline, this app accepts any number of
CSV files. Every alert type that appears in more than one uploaded file is
checked pairwise for a timestamp overlap (using each email's "Time Range"
metadata field) before being merged; any overlapping pair is flagged in the
UI, naming both files, the alert type, and the two overlapping windows, and
you choose how to resolve it before a workbook can be generated.

## Deployment

This is a plain static site: `index.html`, `css/style.css`, and the files
under `js/` (including the vendored `js/lib/papaparse.min.js` and
`js/lib/exceljs.min.js`). To deploy on GitHub Pages, push this repository
and enable Pages for the branch/root you push to; no build step, backend, or
API route is required. To run it locally, just open `index.html` in a
browser (or serve the folder with any static file server).
