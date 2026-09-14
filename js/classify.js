// classify.js
// Direct JS port of classify.py's per-alert-type classifier functions, keyed
// by exact Subject string. Each classifier receives a ctx object (matching
// the ctx produced by the corresponding extractor in extractors.js) and
// returns [classification, explanation]. No em dashes (U+2014) anywhere in
// generated text: colons, commas and parentheses are used instead.

(function (global) {
  "use strict";

  const CDN_ORGS = new Set([
    "cloudflare london llc", "amazon.com inc.", "verisign global registry services",
    "akamai international bv", "google", "apple inc.", "fastly inc.", "sucuri",
  ]);

  function hasActorTag(label) { return /Actor\/\w+/.test(label || ""); }
  function cveList(label) { return (label || "").match(/CVE-\d{4}-\d+/g) || []; }

  function cls_palo_out(ctx) {
    const org = (ctx.org || "").toLowerCase();
    const conf = (ctx.conf || ctx.confidence || "").toLowerCase();
    const label = ctx.label || "";
    if (hasActorTag(label)) {
      const actorMatch = label.match(/Actor\/(\w+)/);
      const actorName = actorMatch ? actorMatch[0] : "Actor/unknown";
      return ["True Positive (Likely)",
        `This specific pair carries an Actor tag (${actorName}), meaning ` +
        `Palo Alto's threat intelligence attributes this indicator to a named threat actor rather than a ` +
        `generic or historic signature, which is a materially stronger basis for a genuine detection ` +
        `regardless of the unverified confidence tier or the hosting provider (${ctx.org}) involved. ` +
        `Action taken was ${ctx.action}. Investigation logic: treat this pair as a priority regardless ` +
        `of its low occurrence count, isolate the internal host ${ctx.host} for a compromise ` +
        `assessment, and do not close this out using the generic CDN reasoning applied to the other rows in ` +
        `this rule.`];
    }
    if (conf === "unverified" && CDN_ORGS.has(org) && label.toLowerCase().includes("status/historic")) {
      return ["False Positive (Likely)",
        `Confidence is unverified, the destination (${ctx.ext}) belongs to ${ctx.org}, a major ` +
        `shared hosting or CDN provider, and the label carries a Status/Historic tag, meaning the indicator ` +
        `was flagged in the past and may no longer be active. This combination is a common source of false ` +
        `positives, since many benign customers share the same address block a threat actor once used. ` +
        `Action taken was ${ctx.action}. Investigation logic: deprioritize unless this specific pair ` +
        `recurs at a growing rate or the destination port changes, which would suggest active rather than ` +
        `historic use.`];
    }
    if (conf === "unverified" && CDN_ORGS.has(org)) {
      return ["False Positive (Likely)",
        `Confidence is unverified and the destination (${ctx.ext}) belongs to ${ctx.org}, a ` +
        `major shared hosting or CDN provider, which is a common source of false positives since many ` +
        `benign customers share the same address block a threat actor once used. Action taken was ` +
        `${ctx.action}. Investigation logic: confirm the internal host ${ctx.host} has a ` +
        `legitimate reason to reach this provider (for example, a SaaS integration); if not, escalate ` +
        `despite the unverified rating.`];
    }
    return ["True Positive (Likely)",
      `Confidence is ${ctx.conf} and the destination (${ctx.ext}, ${ctx.org}) is not a ` +
      `common shared CDN, which raises the likelihood this is a genuine detection rather than reputation ` +
      `noise. Action taken was ${ctx.action}. Investigation logic: prioritize this pair for review, ` +
      `particularly if action is alert rather than a blocking action, since that means the connection was ` +
      `not automatically stopped.`];
  }

  function cls_palo_in(ctx) {
    const action = (ctx.action || "").toLowerCase();
    const label = ctx.label || "";
    const cves = cveList(label);
    const cveTxt = cves.length ? cves.join(", ") : "no specific CVE cited";
    if (["reset-both", "block-ip", "reset-server"].includes(action)) {
      return ["True Positive (Blocked)",
        `Palo Alto's intrusion prevention engine matched an exploit attempt signature (${cveTxt}) from ` +
        `external IP ${ctx.attacker} against internal host ${ctx.target}, and the connection ` +
        `was stopped (${ctx.action}). Investigation logic: confirm ${ctx.target} is patched ` +
        `against ${cveTxt} as a precaution, but treat this specific attempt as contained.`];
    }
    return ["True Positive (Likely)",
      `Palo Alto's intrusion prevention engine matched an exploit attempt signature (${cveTxt}) from external ` +
      `IP ${ctx.attacker} against internal host ${ctx.target}, but the action taken was only ` +
      `${ctx.action}, meaning the traffic was not automatically stopped. Investigation logic: this is a ` +
      `priority item; confirm immediately whether ${ctx.target} is patched against ${cveTxt}, since the ` +
      `exploit attempt reached the host without being blocked.`];
  }

  function cls_blocked_viruses(ctx) {
    return ["True Positive",
      `The firewall's antivirus and anti-spyware engine matched threat signature ${ctx.threat} in ` +
      `traffic from internal host ${ctx.src} to ${ctx.dst}, and the action taken was drop ` +
      `(blocked before delivery), a high confidence detection mechanism. Investigation logic: if this same ` +
      `internal host recurs across several different Full Alert rows in this rule over multiple days, treat ` +
      `it as a stronger indicator of an unresolved infection than any single blocked instance on its own.`];
  }

  function cls_viruses_spyware(ctx) {
    const threat = ctx.threat || "";
    if (threat.toLowerCase().includes("sengrid")) {
      return ["False Positive (Likely)",
        `This entry is triggered by DNS resolution of ${ctx.domain} from ${ctx.src}, matched ` +
        `against the generic heuristic signature ${ctx.threat}. SendGrid is a widely used, legitimate ` +
        `email delivery service, and the generic: prefix on a Palo Alto DNS Security verdict typically ` +
        `reflects a broad heuristic classification rather than a confirmed malware family. Investigation ` +
        `logic: confirm SendGrid is an approved outbound mail relay and request a DNS Security allow list ` +
        `entry for ${ctx.domain} rather than continuing to review this recurring alert.`];
    }
    return ["True Positive (Likely)",
      `Traffic from ${ctx.src} to ${ctx.dst} matched threat signature ${ctx.threat}, which ` +
      `is not the routine SendGrid DNS pattern seen in most of this rule's other entries. Investigation ` +
      `logic: treat this as a priority item precisely because it deviates from the otherwise consistent ` +
      `benign pattern in this rule, and confirm what ${ctx.domain || ctx.threat} actually is ` +
      `before dismissing it.`];
  }

  function cls_high_data_transfer(ctx) {
    return ["False Positive (Likely)",
      `This entry describes an internal to internal transfer between ${ctx.src} and ${ctx.dst} ` +
      `on port ${ctx.port} (SMB when port 445), with volumes such as ${ctx.sent} sent and ` +
      `${ctx.recv} received. Because both endpoints are internal and the pattern repeats at similar ` +
      `volumes, this looks more like a scheduled backup or file replication job than exfiltration, which ` +
      `typically moves data toward an external destination. Investigation logic: confirm with IT operations ` +
      `whether ${ctx.src} and ${ctx.dst} have a documented backup or replication relationship; ` +
      `if not, treat the volume and the use of SMB as a possible ransomware or lateral movement indicator and ` +
      `escalate immediately.`];
  }

  function cls_fw_login(ctx) {
    return ["True Positive",
      `This is an audit log entry confirming that user ${ctx.user} authenticated to ${ctx.fw} ` +
      `from internal IP ${ctx.ip}, so the event itself is factually accurate. Investigation logic: ` +
      `cross reference ${ctx.user} and ${ctx.ip} against the current list of authorized firewall ` +
      `administrators and any approved change window; an unrecognized username or unexpected source IP is ` +
      `the specific condition that should trigger escalation.`];
  }

  function cls_fortinet_login(ctx) {
    return ["True Positive",
      `Confirmed login by ${ctx.user} from ${ctx.ip} to Fortinet device ${ctx.host}. ` +
      `Investigation logic: verify ${ctx.ip} against the employee's expected location or known VPN ` +
      `egress ranges; a login from an unexpected country or impossible travel pattern is the specific signal ` +
      `to escalate, not the successful login itself.`];
  }

  function cls_fw_admin_disabled(ctx) {
    return ["False Positive (Likely)",
      `Repeated lockouts triggered from source IP ${ctx.ip} after 3 bad attempts each time, most ` +
      `commonly caused by an administrator mistyping their own password rather than an attacker, since an ` +
      `attacker guessing an admin credential would typically appear first under Excessive Failed Login ` +
      `Attempts. Investigation logic: confirm with whoever owns ${ctx.ip} that the lockouts were self ` +
      `inflicted; if that IP is not a known admin workstation, escalate as a possible credential guessing ` +
      `attempt against a privileged account.`];
  }

  function cls_cortex(ctx) {
    const action = ctx.action || "";
    if (action.includes("Prevented")) {
      return ["True Positive",
        `Cortex XDR blocked a file or process match on host ${ctx.host} (${ctx.ip}), path ` +
        `${ctx.path}, action Prevented (Blocked). This is endpoint level evidence (a matched file or ` +
        `behavior), which carries materially lower false positive risk than a network reputation match. ` +
        `Investigation logic: no further action strictly required since the file was blocked, but confirm ` +
        `the file's origin (email attachment, download, removable media) to close the delivery vector.`];
    }
    return ["True Positive",
      `Cortex XDR detected a file or process match on host ${ctx.host} (${ctx.ip}), path ` +
      `${ctx.path}, but the action was Detected (Reported) rather than Prevented, meaning it was not ` +
      `automatically blocked. Investigation logic: this is a priority item; confirm the file was manually ` +
      `quarantined or removed from ${ctx.host}, since it was not stopped automatically.`];
  }

  function cls_win_failed_daily(ctx) {
    const acct = ctx.acct || "";
    if (acct.endsWith("$")) {
      return ["False Positive (Likely)",
        `Account ${acct} is a computer or service account (name ends in a dollar sign), not a human user, ` +
        `failing with: ${ctx.reason}. A machine account repeatedly failing authentication with the ` +
        `same error is the signature of a stale scheduled task, service, or cached credential, rather than ` +
        `an external brute force attempt. Investigation logic: identify which host or service is presenting ` +
        `the ${acct} credential and update it; only escalate if the source becomes an external IP.`];
    }
    return ["True Positive (Likely)",
      `Account ${acct} is a human user account failing with: ${ctx.reason}. Investigation logic: check ` +
      `whether this volume of failures against a named human account is unusual for them, and confirm ` +
      `whether a successful login followed shortly after, which would indicate the correct password was ` +
      `eventually found.`];
  }

  function cls_win_admin(ctx) {
    const user = ctx.user || "";
    const logonType = ctx.logon_type || "";
    if (user.endsWith("$") && logonType === "5") {
      return ["False Positive (Likely)",
        `The only account behind all flagged events is ${user}, the domain controller's own computer ` +
        `account, using logon_type 5 (service), meaning this is the server performing routine service ` +
        `level logons on itself rather than a human administrator authenticating. Investigation logic: this ` +
        `pattern is expected background activity for a domain controller; escalate only if a human ` +
        `administrator account begins appearing in this rule, which the current data does not show.`];
    }
    return ["True Positive (Likely)",
      `Administrative logon activity by ${ctx.user} on host ${ctx.host}, logon_type ` +
      `${logonType}. Investigation logic: confirm this account and host pairing against expected IT staff ` +
      `and their usual workstation; an unfamiliar pairing or off hours timing should be escalated.`];
  }

  function cls_win_failed_generic(ctx) {
    const user = ctx.user || "";
    const srcHost = ctx.src_host || "";
    if ((user === '""' || user === "" || user === null) && srcHost.startsWith("::ffff:")) {
      const ip = srcHost.replace("::ffff:", "");
      return ["False Positive (Likely)",
        `No username was captured for these failures from ${ip} (shown as ${srcHost} in IPv6 mapped ` +
        `notation), which is typical of a pre-authentication failure, a misconfigured service, or a ` +
        `network device probing a login endpoint rather than a targeted credential guessing attempt. ` +
        `Investigation logic: identify what device or service ${ip} is; if it is an internal application ` +
        `server or scanner with a known misconfiguration, this is expected noise, if it is unrecognized, ` +
        `investigate further.`];
    }
    return ["True Positive (Likely)",
      `Failed logon for account ${user} from host ${srcHost}, reason: ${ctx.reason}. Investigation ` +
      `logic: check whether many failures against this specific account occurred in a short window, which ` +
      `would indicate targeted password guessing rather than routine user error.`];
  }

  function cls_win_success(ctx) {
    return ["False Positive (Likely)",
      `Successful logon for account ${ctx.user} from host ${ctx.src_host}, logon_type ` +
      `${ctx.logon_type}. Successful interactive logons are the expected baseline of normal domain ` +
      `activity. Investigation logic: cross reference this account and host against expected work patterns, ` +
      `and flag it only if it immediately follows a burst of failed attempts on the same account in the ` +
      `Failed Login Attempts rule, or if the host is one this user does not normally use.`];
  }

  function cls_win_time_change(ctx) {
    const user = ctx.user || "";
    if (["LOCAL SERVICE", "SYSTEM", "NETWORK SERVICE"].includes(user.toUpperCase())) {
      return ["True Positive",
        `The system time on ${ctx.host} was changed by ${user}, a built in operating system account, ` +
        `which is the normal signature of automatic NTP resynchronization rather than a person manually ` +
        `changing the clock. Investigation logic: this event genuinely occurred as logged; only escalate if ` +
        `the acting account changes to a human user, which is a much stronger signal of log tampering.`];
    }
    return ["True Positive (Likely)",
      `The system time on ${ctx.host} was changed by ${user}, a named account rather than a system ` +
      `service. Investigation logic: confirm with ${user} whether this was an intentional, approved change; ` +
      `an unexplained manual time change is a possible log tampering attempt and should be escalated.`];
  }

  function cls_win_created(ctx) {
    const srcUser = (ctx.src_user || "").toLowerCase();
    if (srcUser === "adconnect") {
      return ["False Positive (Likely)",
        `Account ${ctx.user} was created on ${ctx.host} by adconnect, the standard Azure AD ` +
        `Connect service account used to synchronize accounts from a cloud directory into the on premises ` +
        `domain, rather than a human administrator. Investigation logic: confirm ${ctx.user} against ` +
        `an active onboarding record; an account created by any source other than adconnect, or with no ` +
        `onboarding record, is the specific condition that should be escalated.`];
    }
    return ["True Positive (Likely)",
      `Account ${ctx.user} was created on ${ctx.host} by ${ctx.src_user}, a source other ` +
      `than the known Azure AD Connect sync service. Investigation logic: confirm this creation against an ` +
      `active HR onboarding ticket or change request immediately, since it falls outside the routine ` +
      `automated pattern seen elsewhere in this rule.`];
  }

  function cls_win_locked(ctx) {
    return ["False Positive (Likely)",
      `Account ${ctx.user} was locked out (source shown as ${ctx.src_user}). Lockouts are ` +
      `commonly caused by a mistyped password or a stale cached credential on a phone or mapped drive ` +
      `continuing to retry after a password change. Investigation logic: check whether ${ctx.user} ` +
      `recurs across multiple days in this rule, which points to a stale cached credential rather than a one ` +
      `time error, and confirm the source device belongs to the account owner.`];
  }

  function cls_win_password(ctx) {
    return ["False Positive (Likely)",
      `Password change recorded for account ${ctx.user}. Password changes are routine and expected. ` +
      `Investigation logic: treat as a low priority audit trail; review only when investigating this ` +
      `specific account as part of a broader incident, to confirm who changed the password and when relative ` +
      `to any other suspicious activity already under review.`];
  }

  function cls_win_multihost(ctx) {
    const user = ctx.user || "";
    if (user.toUpperCase() === "ANONYMOUS LOGON") {
      return ["True Positive (Likely)",
        `The account flagged on ${ctx.host} is ANONYMOUS LOGON, meaning unauthenticated sessions ` +
        `were established from multiple source hosts (sourceip count of ${ctx.sourceip_count} in ` +
        `this instance), not a normal named user. Investigation logic: this is a priority item regardless ` +
        `of its count; identify what is generating anonymous connections to ${ctx.host}, since ` +
        `legitimate business applications rarely require unauthenticated SMB or RPC access at this volume.`];
    }
    return ["False Positive (Likely)",
      `Named user ${ctx.user} logged into ${ctx.host} from multiple hosts (sourceip count of ` +
      `${ctx.sourceip_count} in this instance). On an environment with hot desking or shared ` +
      `workstations, a moderate number of distinct hosts per day is often unremarkable. Investigation logic: ` +
      `prioritize by the size of the sourceip value (a higher count is more unusual) and confirm the user's ` +
      `role plausibly requires moving between that many devices.`];
  }

  // Tier 2: generic fallback classification. Never guesses True/False
  // Positive; always flags for manual review with an honest explanation.
  function cls_generic_fallback(ctx, subject) {
    const rawPreview = (ctx.raw || "").slice(0, 300);
    return ["Needs Manual Classification",
      `This alert type ("${subject}") has no purpose-built extractor or classifier yet, so it was ` +
      `handled by the generic schema-agnostic fallback: rows were grouped by whatever IP-shaped or ` +
      `hostname-shaped tokens were found in their fields (${(ctx.tokens || []).join(", ") || "none found"}), ` +
      `and any Count or eventcount field present was summed. Investigation logic: a human should review a ` +
      `sample of the raw rows for this alert type, decide the correct grouping key and true/false positive ` +
      `logic, and graduate this alert type to a purpose-built extractor and classifier (see the README for the ` +
      `exact steps). Sample raw field values from one row: ${rawPreview}`];
  }

  const CLASSIFIERS = {
    "GFR Media - WARNING - Palo Alto - Accepted Malicious Connections Out": cls_palo_out,
    "GFR Media - WARNING - Palo Alto - Accepted Malicious Connections In": cls_palo_in,
    "Search Results: GFR Media - Daily Report - Palo Alto - Blocked Viruses & Spyware Report": cls_blocked_viruses,
    "GFR Media - WARNING - Palo Alto - Viruses & Spyware Alert": cls_viruses_spyware,
    "GFR Media - Daily Report - Palo Alto - Viruses & Spyware Report": cls_viruses_spyware,
    "GFR Media - WARNING - Palo Alto - High Data Transfer Usage": cls_high_data_transfer,
    "GFR Media - Critical Alert - Successful User Logins to Firewall (Palo Alto)": cls_fw_login,
    "GFR Media / LinkActiv - Critical Alert - Fortinet - Successful User Login - Off Hours": cls_fortinet_login,
    "GFR Media / LinkActiv - Critical Alert - Fortinet - Successful User Login - Off hours": cls_fortinet_login,
    "GFR Media / LinkActiv - Daily Report - Fortinet - Admin Login Disabled (Account Locked Out)": cls_fw_admin_disabled,
    "GFR Media / LinkActiv - Daily Report - Fortinet - Successful User Login": cls_fortinet_login,
    "GFR Media - Daily Report - Cortex XDR - Malware Detected": cls_cortex,
    "GFR Media - Critical Alert - Cortex XDR - Malware Detected": cls_cortex,
    "GFR Media - Windows Failed Logins (Daily Report)": cls_win_failed_daily,
    "GFR Media/LinkActiv - Daily Report - Windows - Admin Attempts by User": cls_win_admin,
    "GFR Media/LinkActiv - Daily Report - Windows - Failed Login Attempts": cls_win_failed_generic,
    "GFR Media/LinkActiv - Daily Report - Windows - Successful Login": cls_win_success,
    "GFR Media/LinkActiv - Daily Report - Windows - System Time Change": cls_win_time_change,
    "GFR Media/LinkActiv - Daily Report - Windows - User Account Created": cls_win_created,
    "GFR Media/LinkActiv - Daily Report - Windows - User Account Created - Off Hours": cls_win_created,
    "GFR Media/LinkActiv - Daily Report - Windows - User Account Created - Prohibited system": cls_win_created,
    "GFR Media/LinkActiv - Daily Report - Windows - User Account Locked": cls_win_locked,
    "GFR Media/LinkActiv - Daily Report - Windows - User Account Password Changes": cls_win_password,
    "GFR Media/LinkActiv - Daily Report - Windows - User Login from Multiple Hosts": cls_win_multihost,
  };

  global.SocClassify = { CLASSIFIERS, cls_generic_fallback, CDN_ORGS, hasActorTag, cveList };
})(window);
