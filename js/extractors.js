// extractors.js
// Direct JS port of extract_entities.py's per-alert-type extractor functions,
// keyed by exact Subject string (Tier 1: known alert types), plus a
// schema-agnostic Tier 2 fallback extractor for any Subject not in the map.
//
// Each Tier 1 extractor receives (header, headerLower, data, runAt) for one
// row and returns { key: [...], disp: "...", ctx: {...} } exactly mirroring
// the Python (key, disp, ctx) tuple.

(function (global) {
  "use strict";

  function get(headerLower, data, name) {
    name = name.toLowerCase();
    const idx = headerLower.indexOf(name);
    return idx === -1 ? "" : (data[idx] === undefined ? "" : data[idx]);
  }

  function toInt(v) {
    if (v === null || v === undefined) return null;
    const s = String(v).trim().replace(/,/g, "");
    return /^-?\d+$/.test(s) ? parseInt(s, 10) : null;
  }

  // ---------------- Tier 1: known alert type extractors ----------------

  function ex_palo_out(h, hl, d) {
    const host = get(hl, d, "Host");
    const ext = get(hl, d, "external_threat");
    const port = get(hl, d, "dstport");
    const label = get(hl, d, "label_name");
    const org = get(hl, d, "organization");
    const action = get(hl, d, "action");
    const conf = get(hl, d, "malicious_confidence");
    return {
      key: [host, ext, port],
      disp: `Internal host ${host} to external IP ${ext} (${org}) on port ${port}`,
      ctx: { action, confidence: conf, label, org, host, ext, port },
    };
  }

  function ex_palo_in(h, hl, d) {
    const target = get(hl, d, "ip_atacada") || get(hl, d, "Host");
    const attacker = get(hl, d, "ip_atacante");
    const label = get(hl, d, "label_name");
    const action = get(hl, d, "action");
    const conf = get(hl, d, "malicious_confidence");
    return {
      key: [target, attacker],
      disp: `External attacker IP ${attacker} against internal host ${target}`,
      ctx: { action, confidence: conf, label, target, attacker },
    };
  }

  function ex_blocked_viruses(h, hl, d) {
    const src = get(hl, d, "src_ip");
    const dst = get(hl, d, "dest_ip");
    const threat = get(hl, d, "threat_content_name");
    const action = get(hl, d, "action");
    return {
      key: [src, dst, threat],
      disp: `Internal host ${src} to ${dst}, threat ${threat}`,
      ctx: { action, src, dst, threat },
    };
  }

  function ex_viruses_spyware(h, hl, d) {
    const src = get(hl, d, "src_ip");
    const dst = get(hl, d, "dest_ip");
    const domain = get(hl, d, "url_domain");
    const threat = get(hl, d, "threat_name") || domain;
    return {
      key: [src, dst, threat],
      disp: `Internal host ${src} to ${dst} (${domain}), threat ${threat}`,
      ctx: { src, dst, threat, domain },
    };
  }

  function ex_high_data_transfer(h, hl, d) {
    const src = get(hl, d, "src_ip");
    const dst = get(hl, d, "dest_ip");
    const dport = get(hl, d, "dest_port");
    return {
      key: [src, dst, dport],
      disp: `Internal host ${src} to internal host ${dst} on port ${dport}`,
      ctx: { src, dst, port: dport, sent: get(hl, d, "gbytes_sent"), recv: get(hl, d, "gbytes_recv") },
    };
  }

  const MSG_LOGIN_RE = /User\s+"([^"]+)"\s+attempted to access (\S+).*?from [^(]*\(([\d.]+)\)/;
  function ex_fw_login(h, hl, d) {
    const msg = get(hl, d, "message");
    const m = MSG_LOGIN_RE.exec(msg);
    let user = "unknown", fw = "unknown", ip = "unknown";
    if (m) { user = m[1]; fw = m[2]; ip = m[3]; }
    return {
      key: [user, ip, fw],
      disp: `User ${user} from internal IP ${ip} to firewall ${fw}`,
      ctx: { user, ip, fw },
    };
  }

  const MSG_DISABLED_RE = /Login disabled from IP ([\d.]+) for (\d+) seconds because of (\d+) bad attempts/;
  function ex_fw_admin_disabled(h, hl, d) {
    const msg = get(hl, d, "message");
    const m = MSG_DISABLED_RE.exec(msg);
    const ip = m ? m[1] : "unknown";
    return { key: [ip], disp: `Login lockouts triggered from source IP ${ip}`, ctx: { ip } };
  }

  function ex_fortinet_login(h, hl, d) {
    const user = get(hl, d, "src_user");
    const ip = get(hl, d, "src_ip");
    const host = get(hl, d, "dest_host");
    return {
      key: [user, ip, host],
      disp: `User ${user} from IP ${ip} to Fortinet device ${host}`,
      ctx: { user, ip, host },
    };
  }

  function ex_cortex_malware(h, hl, d) {
    const host = get(hl, d, "host name");
    const ip = get(hl, d, "host ip");
    const path = get(hl, d, "path");
    const action = get(hl, d, "action");
    const status = get(hl, d, "status");
    return {
      key: [host, path],
      disp: `Host ${host} (${ip}), file ${path}`,
      ctx: { host, ip, path, action, status, desc: get(hl, d, "description") },
    };
  }

  function ex_win_failed_logins_daily(h, hl, d) {
    const acct = get(hl, d, "account_name");
    const reason = get(hl, d, "failure_reason");
    return { key: [acct, reason], disp: `Account ${acct}, reason: ${reason}`, ctx: { acct, reason } };
  }

  function ex_win_admin_attempts(h, hl, d) {
    const user = get(hl, d, "src_user");
    const host = get(hl, d, "dest_host") || get(hl, d, "src_host");
    return {
      key: [user, host],
      disp: `Administrator ${user} on host ${host}`,
      ctx: { user, host, logon_type: get(hl, d, "logon_type") },
    };
  }

  function ex_win_failed_login_attempts(h, hl, d) {
    const user = get(hl, d, "dest_user");
    const srcHost = get(hl, d, "src_host");
    const reason = get(hl, d, "fail_reason");
    return {
      key: [user, srcHost, reason],
      disp: `Account ${user} from host ${srcHost}, reason: ${reason}`,
      ctx: { user, src_host: srcHost, reason },
    };
  }

  function ex_win_successful_login(h, hl, d) {
    const user = get(hl, d, "dest_user");
    const srcHost = get(hl, d, "src_host");
    return {
      key: [user, srcHost],
      disp: `Account ${user} from host ${srcHost}`,
      ctx: { user, src_host: srcHost, logon_type: get(hl, d, "logon_type") },
    };
  }

  function ex_win_system_time_change(h, hl, d) {
    const host = get(hl, d, "dest_host");
    const user = get(hl, d, "src_user");
    return { key: [host, user], disp: `Host ${host}, changed by ${user}`, ctx: { host, user } };
  }

  function ex_win_user_created(h, hl, d) {
    const user = get(hl, d, "dest_user");
    const srcUser = get(hl, d, "src_user");
    const host = get(hl, d, "dest_host");
    return {
      key: [user],
      disp: `Account ${user} created on ${host} by ${srcUser}`,
      ctx: { user, src_user: srcUser, host },
    };
  }

  function ex_win_account_locked(h, hl, d) {
    const user = get(hl, d, "dest_user");
    const srcUser = get(hl, d, "src_user");
    return { key: [user], disp: `Account ${user} (source ${srcUser})`, ctx: { user, src_user: srcUser } };
  }

  function ex_win_password_change(h, hl, d) {
    const user = get(hl, d, "dest_user");
    return { key: [user], disp: `Account ${user}`, ctx: { user } };
  }

  function ex_win_multi_host(h, hl, d) {
    const user = get(hl, d, "dest_user");
    const host = get(hl, d, "dest_host");
    return {
      key: [user, host],
      disp: `Account ${user} on ${host}`,
      ctx: { user, host, sourceip_count: get(hl, d, "sourceip") },
    };
  }

  const EXTRACTORS = {
    "GFR Media - WARNING - Palo Alto - Accepted Malicious Connections Out": ex_palo_out,
    "GFR Media - WARNING - Palo Alto - Accepted Malicious Connections In": ex_palo_in,
    "Search Results: GFR Media - Daily Report - Palo Alto - Blocked Viruses & Spyware Report": ex_blocked_viruses,
    "GFR Media - WARNING - Palo Alto - Viruses & Spyware Alert": ex_viruses_spyware,
    "GFR Media - Daily Report - Palo Alto - Viruses & Spyware Report": ex_viruses_spyware,
    "GFR Media - WARNING - Palo Alto - High Data Transfer Usage": ex_high_data_transfer,
    "GFR Media - Critical Alert - Successful User Logins to Firewall (Palo Alto)": ex_fw_login,
    "GFR Media / LinkActiv - Critical Alert - Fortinet - Successful User Login - Off Hours": ex_fortinet_login,
    "GFR Media / LinkActiv - Critical Alert - Fortinet - Successful User Login - Off hours": ex_fortinet_login,
    "GFR Media / LinkActiv - Daily Report - Fortinet - Admin Login Disabled (Account Locked Out)": ex_fw_admin_disabled,
    "GFR Media / LinkActiv - Daily Report - Fortinet - Successful User Login": ex_fortinet_login,
    "GFR Media - Daily Report - Cortex XDR - Malware Detected": ex_cortex_malware,
    "GFR Media - Critical Alert - Cortex XDR - Malware Detected": ex_cortex_malware,
    "GFR Media - Windows Failed Logins (Daily Report)": ex_win_failed_logins_daily,
    "GFR Media/LinkActiv - Daily Report - Windows - Admin Attempts by User": ex_win_admin_attempts,
    "GFR Media/LinkActiv - Daily Report - Windows - Failed Login Attempts": ex_win_failed_login_attempts,
    "GFR Media/LinkActiv - Daily Report - Windows - Successful Login": ex_win_successful_login,
    "GFR Media/LinkActiv - Daily Report - Windows - System Time Change": ex_win_system_time_change,
    "GFR Media/LinkActiv - Daily Report - Windows - User Account Created": ex_win_user_created,
    "GFR Media/LinkActiv - Daily Report - Windows - User Account Created - Off Hours": ex_win_user_created,
    "GFR Media/LinkActiv - Daily Report - Windows - User Account Created - Prohibited system": ex_win_user_created,
    "GFR Media/LinkActiv - Daily Report - Windows - User Account Locked": ex_win_account_locked,
    "GFR Media/LinkActiv - Daily Report - Windows - User Account Password Changes": ex_win_password_change,
    "GFR Media/LinkActiv - Daily Report - Windows - User Login from Multiple Hosts": ex_win_multi_host,
  };

  // ---------------- Tier 2: generic schema-agnostic fallback ----------------
  // Does not depend on knowing column names in advance. Scans all field
  // values in the row for IP-shaped and hostname-shaped tokens and groups by
  // the distinct sorted set found. Still sums Count/eventcount fields
  // universally (that detection lives in the grouping engine, not here).

  const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
  const IPV6_RE = /\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/g;
  const HOSTNAME_RE = /\b[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?){1,}\b/g;

  function extractTokens(text) {
    const found = new Set();
    if (!text) return found;
    const s = String(text);
    let m;
    IPV4_RE.lastIndex = 0;
    while ((m = IPV4_RE.exec(s))) found.add(m[0]);
    IPV6_RE.lastIndex = 0;
    while ((m = IPV6_RE.exec(s))) { if (m[0].includes(":") && m[0].split(":").length > 2) found.add(m[0]); }
    HOSTNAME_RE.lastIndex = 0;
    while ((m = HOSTNAME_RE.exec(s))) { if (!IPV4_RE.test(m[0])) found.add(m[0]); }
    return found;
  }

  // Generic fallback extractor: receives (header, headerLower, data) for one
  // row, returns the same { key, disp, ctx } shape as Tier 1 extractors.
  function ex_generic_fallback(header, headerLower, data) {
    const tokens = new Set();
    for (const v of data) {
      for (const t of extractTokens(v)) tokens.add(t);
    }
    const sorted = Array.from(tokens).sort();
    const key = sorted.length ? sorted : ["(no ip/hostname token found)"];
    const disp = sorted.length
      ? `Entities found: ${sorted.join(", ")}`
      : "No IP or hostname shaped token found in this row's fields";
    return { key, disp, ctx: { tokens: sorted, raw: header.map((h, i) => `${h}=${data[i] || ""}`).join(" | ") } };
  }

  global.SocExtractors = { EXTRACTORS, ex_generic_fallback, get, toInt, extractTokens };
})(window);
