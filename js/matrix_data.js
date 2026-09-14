// matrix_data.js
// Direct JS port of matrix_data.py's ROWS: static per-alert-type Critical
// Level table plus the "no occurrences this period" placeholder rows and
// alert-type-level explanation used when an alert type is present in the
// known list but generates zero rows. Independent of true/false positive
// determination for this period's actual occurrences.
//
// No em dashes (U+2014) anywhere in this file.

(function (global) {
  "use strict";

  const ROWS = [
    { alert: "GFR Media - WARNING - Palo Alto - Accepted Malicious Connections Out", level: "High" },
    { alert: "GFR Media - WARNING - Palo Alto - Accepted Malicious Connections In", level: "Critical" },
    { alert: "GFR Media - Daily Report - Cortex XDR - Malware Detected", level: "Critical" },
    { alert: "GFR Media - Critical Alert - Cortex XDR - Malware Detected", level: "Critical" },
    { alert: "Search Results: GFR Media - Daily Report - Palo Alto - Blocked Viruses & Spyware Report", level: "High" },
    { alert: "GFR Media - WARNING - Palo Alto - Viruses & Spyware Alert", level: "Low" },
    { alert: "GFR Media - Daily Report - Palo Alto - Viruses & Spyware Report", level: "Low" },
    { alert: "GFR Media - WARNING - Palo Alto - High Data Transfer Usage", level: "Medium" },
    { alert: "GFR Media - Critical Alert - Successful User Logins to Firewall (Palo Alto)", level: "Medium" },
    { alert: "GFR Media - Windows Failed Logins (Daily Report)", level: "Medium" },
    { alert: "GFR Media / LinkActiv - Critical Alert - Fortinet - Successful User Login - Off Hours", level: "Medium" },
    { alert: "GFR Media / LinkActiv - Critical Alert - Fortinet - Successful User Login - Off hours", level: "Medium" },
    { alert: "GFR Media / LinkActiv - Daily Report - Fortinet - Admin Login Disabled (Account Locked Out)", level: "Medium" },
    { alert: "GFR Media / LinkActiv - Daily Report - Fortinet - Excessive Failed Login Attempts", level: "High",
      zero_explanation: "No emails in the analyzed period contained data for this rule (all returned No data), so there is no event to classify as a true or false positive. This rule is inherently high severity by design, since it is meant to catch password guessing or brute force activity against Fortinet accounts. Investigation logic if it fires in the future: check whether the failed attempts target one account (credential guessing) or many accounts from one source (a spray attack), and treat both patterns as a true positive requiring immediate password reset and source IP block." },
    { alert: "GFR Media / LinkActiv - Daily Report - Fortinet - Group Deleted", level: "Medium",
      zero_explanation: "No emails in the analyzed period contained data for this rule. Group deletions on network infrastructure are infrequent and moderately impactful, since removing a group can unintentionally revoke access for its members. Investigation logic if it fires in the future: confirm the deletion matches an approved change ticket before treating it as routine administration." },
    { alert: "GFR Media / LinkActiv - Daily Report - Fortinet - New Group Added", level: "Medium",
      zero_explanation: "No emails in the analyzed period contained data for this rule. Creating a new administrative or access group is a moderate impact change, since it can be a step toward setting up unauthorized access. Investigation logic if it fires in the future: confirm the group creation matches an approved change ticket and review which permissions the new group carries before considering it routine." },
    { alert: "GFR Media / LinkActiv - Daily Report - Fortinet - Successful User Login", level: "Low" },
    { alert: "GFR Media / LinkActiv - Daily Report - Fortinet - System Stopped", level: "High",
      zero_explanation: "No emails in the analyzed period contained data for this rule. An unplanned stop of a Fortinet system is high impact, since it can indicate tampering, a denial of service condition, or an availability failure that removes a security control from service. Investigation logic if it fires in the future: confirm whether the stop coincides with a scheduled maintenance window before treating it as a genuine security event." },
    { alert: "GFR Media / LinkActiv - Daily Report - Fortinet - System Time Change Attempts", level: "Medium",
      zero_explanation: "No emails in the analyzed period contained data for this rule. Time changes on network infrastructure can be legitimate (NTP resynchronization) or an attempt to disrupt log correlation and timestamp based investigations. Investigation logic if it fires in the future: confirm the change aligns with a known NTP source or maintenance activity; an unexplained manual time change should be treated as a possible log tampering attempt." },
    { alert: "GFR Media / LinkActiv - Daily Report - Fortinet - User Added to Privilege Group", level: "High",
      zero_explanation: "No emails in the analyzed period contained data for this rule. Adding a user to a privileged group is a high impact change by nature, since it directly expands an account's access. Investigation logic if it fires in the future: confirm the addition matches an approved access request and that the requesting and approving parties are different people, before accepting it as routine." },
    { alert: "GFR Media / LinkActiv - Daily Report - Fortinet - User Created", level: "Medium",
      zero_explanation: "No emails in the analyzed period contained data for this rule. New account creation on network infrastructure is routine during onboarding but still worth a light check. Investigation logic if it fires in the future: confirm the new account against an active onboarding ticket or change request." },
    { alert: "GFR Media / LinkActiv - Daily Report - Fortinet - User Created - Off Hours", level: "High",
      zero_explanation: "No emails in the analyzed period contained data for this rule. Account creation outside business hours carries materially higher risk than the daytime equivalent, since it removes the natural oversight of colleagues and helpdesk staff being present. Investigation logic if it fires in the future: treat as a priority item and confirm the creating account and timing against an approved after hours change window before accepting it as routine." },
    { alert: "GFR Media / LinkActiv - Daily Report - Fortinet - User Deleted", level: "Medium",
      zero_explanation: "No emails in the analyzed period contained data for this rule. Investigation logic if it fires in the future: confirm the deletion matches an offboarding ticket; a deletion with no matching ticket, especially for a privileged account, should be escalated." },
    { alert: "GFR Media / LinkActiv - Daily Report - Fortinet - User Login From Multiple Hosts", level: "Medium",
      zero_explanation: "No emails in the analyzed period contained data for this rule. A single account authenticating from several distinct hosts in a short window can indicate credential sharing or a compromised credential in use by an attacker alongside the legitimate owner. Investigation logic if it fires in the future: compare the number and location of hosts against what is plausible for that user's normal work pattern." },
    { alert: "GFR Media / LinkActiv - Daily Report - Fortinet - User Password Changes", level: "Low",
      zero_explanation: "No emails in the analyzed period contained data for this rule. Password changes are routine and low risk on their own. Investigation logic if it fires in the future: review this rule mainly as supporting context during a broader account investigation, to establish when a password was last changed relative to suspicious activity." },
    { alert: "GFR Media/LinkActiv - Daily Report - Windows - Admin Attempts by User", level: "Medium" },
    { alert: "GFR Media/LinkActiv - Daily Report - Windows - Failed Login Attempts", level: "Medium" },
    { alert: "GFR Media/LinkActiv - Daily Report - Windows - Group Deleted (Changes to Administrative Groups)", level: "High",
      zero_explanation: "No emails in the analyzed period contained data for this rule. Deleting an administrative group is high impact, since it can strip access from every member at once or be used to cover tracks after a privilege escalation. Investigation logic if it fires in the future: confirm the deletion against an approved change ticket immediately, since this is one of the higher impact changes possible on a domain." },
    { alert: "GFR Media/LinkActiv - Daily Report - Windows - New Group Added (Successful Group Creations)", level: "Medium",
      zero_explanation: "No emails in the analyzed period contained data for this rule. Investigation logic if it fires in the future: confirm the new group against an approved change ticket and review what permissions or group memberships were assigned to it shortly after creation." },
    { alert: "GFR Media/LinkActiv - Daily Report - Windows - Service Stopped", level: "Medium",
      zero_explanation: "No emails in the analyzed period contained data for this rule. An unexpected service stop can indicate tampering (for example, disabling security software) or a routine maintenance action. Investigation logic if it fires in the future: identify which service stopped and confirm whether it was a planned maintenance action before ruling out tampering, especially if the service is security related (antivirus, logging, backup)." },
    { alert: "GFR Media/LinkActiv - Daily Report - Windows - Successful Login", level: "Low" },
    { alert: "GFR Media/LinkActiv - Daily Report - Windows - System Restarted", level: "Medium",
      zero_explanation: "No emails in the analyzed period contained data for this rule. An unexpected restart can indicate instability, patching, or an attempt to clear volatile evidence after an intrusion. Investigation logic if it fires in the future: confirm the restart against a known patch or maintenance window before ruling out a security cause." },
    { alert: "GFR Media/LinkActiv - Daily Report - Windows - System Time Change", level: "Low" },
    { alert: "GFR Media/LinkActiv - Daily Report - Windows - User Account Created", level: "Medium" },
    { alert: "GFR Media/LinkActiv - Daily Report - Windows - User Account Created - Off Hours", level: "High" },
    { alert: "GFR Media/LinkActiv - Daily Report - Windows - User Account Created - Prohibited system", level: "High" },
    { alert: "GFR Media/LinkActiv - Daily Report - Windows - User Account Deleted", level: "Medium",
      zero_explanation: "No emails in the analyzed period contained data for this rule. Investigation logic if it fires in the future: confirm the deletion against an offboarding ticket; an unexplained deletion, particularly of a privileged or service account, should be escalated." },
    { alert: "GFR Media/LinkActiv - Daily Report - Windows - User Account Locked", level: "Medium" },
    { alert: "GFR Media/LinkActiv - Daily Report - Windows - User Account Password Changes", level: "Low" },
    { alert: "GFR Media/LinkActiv - Daily Report - Windows - User Added to Privilege Groups", level: "High",
      zero_explanation: "No emails in the analyzed period contained data for this rule. Adding a user to a privileged group (such as Domain Admins) is high impact by nature, since it directly expands an account's access without necessarily requiring a new logon to notice. Investigation logic if it fires in the future: confirm the addition against an approved access request with a named approver different from the requester, and treat any addition with no matching request as a likely true positive requiring immediate review." },
    { alert: "GFR Media/LinkActiv - Daily Report - Windows - User Login from Multiple Hosts", level: "Medium" },
  ];

  const LEVEL_BY_ALERT = {};
  for (const r of ROWS) LEVEL_BY_ALERT[r.alert] = r.level;

  const ZERO_COUNT_ALERTS = ROWS.filter((r) => r.zero_explanation);

  global.SocMatrixData = { ROWS, LEVEL_BY_ALERT, ZERO_COUNT_ALERTS };
})(window);
