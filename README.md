# 🛡️ VaultScan — Advanced JWT Security Analysis & Learning Platform

> **An offline, enterprise-grade cybersecurity capsule project for JSON Web Token (JWT) vulnerability inspection, cryptographic hygiene auditing, differential analysis, and defense education.**

---

## 📋 Table of Contents
1. [Abstract](#-abstract)
2. [Problem Statement](#-problem-statement)
3. [Objectives](#-objectives)
4. [Why JWT Security Matters (Real-World Breaches)](#-why-jwt-security-matters)
5. [Basic vs. Advanced VaultScan Differentiation](#-basic-vs-advanced-vaultscan)
6. [Architecture & System Design](#-architecture--system-design)
7. [The 12 Core Security Checks & MITRE Mappings](#-the-12-core-security-checks)
8. [Risk Scoring & Grading Algorithm](#-risk-scoring--grading-algorithm)
9. [Module Descriptions](#-module-descriptions)
10. [REST API Documentation](#-rest-api-documentation)
11. [Installation & Setup](#-installation--setup)
12. [Running Instructions](#-running-instructions)
13. [Testing Suite & Verification](#-testing-suite--verification)
14. [User Interface Overview](#-user-interface-overview)
15. [Security Limitations & Boundaries](#-security-limitations--boundaries)
16. [Future Enhancements](#-future-enhancements)
17. [Conclusion](#-conclusion)

---

## 🌟 Abstract
**VaultScan** is a specialized, 100% offline security assessment suite and interactive laboratory for evaluating the cryptographic robustness, structure, and claim hygiene of JSON Web Tokens (RFC 7519). Built with Node.js, Express, and modern vanilla web technologies, VaultScan inspects tokens without requiring backend verification keys, performs 12 distinct automated vulnerability audits (including dictionary cracking against 45+ common keys, algorithm confusion, directory traversal in key locators, and sensitive credential detection), assigns calibrated risk scores (0–100) and letter grades (A–F), and provides plain-English remediation guidance with copyable code fixes. Designed for academic viva demonstrations, defense labs, and security engineers, it features a differential token comparison engine, educational tampering simulator, secret entropy analyzer, interactive attack scenario lab, and one-click printable audit reports.

---

## ❗ Problem Statement
JSON Web Tokens (JWTs) have become the de-facto standard for stateless authentication in modern cloud and microservice architectures. However, misconfigured JWT implementations remain one of the most widespread causes of critical authentication bypasses in production:
1. **Misconception of Privacy:** Developers frequently mistake Base64URL encoding for encryption, transmitting plaintext passwords, API keys, and Personally Identifiable Information (PII) across public networks.
2. **Algorithm Confusion & "none" Bypass:** Verifiers failing to whitelist algorithms permit adversaries to submit forged tokens with `alg: "none"` or re-sign asymmetric tokens with public keys as HMAC secrets.
3. **Weak & Guessable Shared Secrets:** HMAC secrets frequently use dictionary words (e.g. `secret123`, `jwt`), allowing attackers to brute-force the key offline in seconds and forge administrative access.
4. **Missing Session Expirations:** Tokens lacking `exp` boundaries never expire, granting attackers permanent access if tokens are leaked in browser caches or proxy access logs.

Traditional tools often require cloud connectivity, API keys, or specialized CLI environments that are unsuitable for classroom demonstrations and rapid local security reviews.

---

## 🎯 Objectives
- **Zero-Trust Offline Inspection:** Safely parse and audit untrusted JWTs entirely inside an isolated local Node.js environment without sending tokens to third-party endpoints.
- **RFC 7519 & MITRE ATT&CK Grounding:** Directly correlate discovered token anomalies to standardized threat tactics and techniques.
- **Educational Tampering Sandbox:** Demonstrate visually and cryptographically why altering claims in transit invalidates signatures and triggers server rejection.
- **Differential Token Comparison:** Provide granular claim diffing to instantly detect privilege escalations (e.g., `role: user → admin`) and modified scopes.
- **Automated Audit Reporting:** Produce downloadable and print-ready compliance reports for coursework, security reviews, and viva examinations.

---

## 🚨 Why JWT Security Matters (Real-World Breaches)

### Case 1: The `alg: none` Authentication Bypass
In numerous open-source libraries and enterprise single sign-on (SSO) gateways, implementations accepted tokens containing `{"alg": "none"}` without verifying signatures. Attackers modified their user identity payload to administrative accounts, dropped the signature section, and gained unauthorized system-wide access without possessing any secret key (MITRE T1550.001).

### Case 2: Key Confusion & Asymmetric Secret Forgery (RS256 → HS256)
During multiple high-profile security audits (including major identity providers and SaaS platforms), APIs configured to verify RS256 asymmetric signatures used verification libraries that did not restrict algorithms. Attackers obtained the publicly accessible RSA public key, signed a forged token using HMAC-SHA256 (HS256) using the public key as the secret passphrase, and successfully bypassed authentication because the library treated the key string as a valid symmetric key.

---

## ⚖️ Basic vs. Advanced VaultScan Differentiation

| Capability | Basic VaultScan | Advanced VaultScan (Current Platform) |
|---|:---:|:---:|
| **JWT Decoding (Header, Payload, Sig)** | ✅ Yes | ✅ Yes |
| **12 Security Checks & Scoring (A–F)** | ✅ Yes | ✅ Yes |
| **Weak Secret Dictionary Cracking** | ✅ Yes | ✅ Yes |
| **In-Memory History (Last 20 Tokens)** | ✅ Yes | ✅ Yes |
| **Dynamic Test Token Generation** | ✅ Yes | ✅ Yes |
| **Differential JWT Comparison Engine** | ❌ No | ✅ **Yes (Detects privilege escalations & claim diffs)** |
| **Interactive Tampering Sandbox** | ❌ No | ✅ **Yes (Visual 4-step flow + rejection analysis)** |
| **Secret Strength & Entropy Analyzer** | ❌ No | ✅ **Yes (Shannon entropy + pattern rules)** |
| **Security Dashboard & Trend Visualizer** | ❌ No | ✅ **Yes (Real-time charts + trajectory metrics)** |
| **"Improve My Score" Simulator** | ❌ No | ✅ **Yes (Interactive checklist + score gain)** |
| **Attack Scenario Lab** | ❌ No | ✅ **Yes (8 interactive pre-configured exploits)** |
| **4-Pillar Security Profile** | ❌ No | ✅ **Yes (Auth, Claims, Crypto, Lifetime)** |
| **Printable Audit Report Generator** | ❌ No | ✅ **Yes (Print-to-PDF & HTML export)** |
| **Educational Learning Flashcards** | ❌ No | ✅ **Yes (12 comprehensive guide cards)** |
| **Privacy Mode & Session Wipe** | ❌ No | ✅ **Yes (Zero residual memory footprint)** |

---

## 🏗️ Architecture & System Design

```
+-----------------------------------------------------------------------------------+
|                           VAULTSCAN WEB FRONTEND                                  |
|         (Vanilla HTML5 / CSS3 Cyber Theme / Tabbed Modular Architecture)          |
+-----------------------------------------------------------------------------------+
       |                  |                |                |               |
 [Dashboard.js]    [App.js (Core)]  [Compare.js]    [Tamper.js]   [Reports.js]
       |                  |                |                |               |
+-----------------------------------------------------------------------------------+
|                        REST API ENGINE (server.js)                                |
|        Express.js Server (Port 3000) - 100% Localhost - In-Memory Store           |
+-----------------------------------------------------------------------------------+
       |                  |                |                |               |
 [analyzer.js]     [jwtUtils.js]    [scoring.js]    [recommend.js]  [learningData.js]
  - 12 Checks       - Base64URL      - Entropy       - Checklist     - 12 Flashcards
  - Scoring & MITRE - Dict Attack    - 4 Pillars     - Code Fixes    - 8 Scenarios
       |                  |                |                |               |
+-----------------------------------------------------------------------------------+
|                      CRYPTOGRAPHIC ENGINE (jsonwebtoken)                          |
+-----------------------------------------------------------------------------------+
```

---

## 🔍 The 12 Core Security Checks

| # | Check Identifier | Severity | MITRE ATT&CK | Problem Description | Recommended Remediation |
|---|---|:---:|:---:|---|---|
| **1** | `alg_none` | **CRITICAL** | T1550.001 | Token uses unsigned "none" algorithm; allows arbitrary claim forgery. | Reject `alg:none` on backend; enforce strict whitelist of ciphers. |
| **2** | `weak_secret` | **CRITICAL** | T1110.002 | Token signed with a dictionary passphrase (e.g. `secret123`). | Rotate to a cryptographically random 256-bit secret key. |
| **3** | `alg_confusion` | **HIGH** | T1550.001 | Asymmetric algorithm (RS256) vulnerable to HMAC key confusion. | Pin algorithms explicitly in verification middleware. |
| **4** | `missing_exp` | **HIGH** | CWE-613 | Token lacks expiration claim; permanently reusable if compromised. | Always set `exp` claim; cap access tokens to 15–60 minutes. |
| **5** | `expired` | **MEDIUM** | CWE-613 | Token expiration timestamp is in the past. | Reject token at gateway; initiate refresh token exchange. |
| **6** | `excessive_expiry` | **MEDIUM** | CWE-613 | Lifetime exceeds 24 hours (86,400s), expanding attack window. | Issue short-lived tokens with rotating refresh cookies. |
| **7** | `sensitive_payload` | **HIGH** | T1552.001 | Plaintext passwords, SSNs, or API keys exposed in payload. | Store only opaque IDs; fetch sensitive data server-side. |
| **8** | `missing_iss` | **LOW** | CWE-287 | Issuer claim missing; authorization authority unverified. | Add and verify `iss` domain in API gateway middleware. |
| **9** | `missing_aud` | **LOW** | CWE-287 | Audience claim missing; token reusable across multiple microservices. | Set `aud` claim restricted to target API service. |
| **10** | `kid_traversal` | **HIGH** | T1083 | Key ID parameter contains path traversal characters (`../`, `/`). | Sanitize `kid` and look up keys from a key map dictionary. |
| **11** | `large_payload` | **LOW** | N/A | Token length exceeds 4,096 bytes; degrades HTTP performance. | Minimize payload size; avoid storing large object state in JWT. |
| **12** | `jku_external` | **HIGH** | T1195 | Header points to external JWKS URL; risk of key injection and SSRF. | Enforce strict domain whitelist on all remote key retrieval URLs. |

---

## 🧮 Risk Scoring & Grading Algorithm

VaultScan initializes every token with an optimal baseline score of **100 points** and applies deductions according to the severity of identified vulnerabilities:

$$	ext{Score} = maxleft(0, 100 - sum 	ext{Deductions}ight)$$

### Severity Weights:
- **CRITICAL:** $-40$ points
- **HIGH:** $-25$ points
- **MEDIUM:** $-10$ points
- **LOW:** $-5$ points

### Letter Grade Mapping:
- **Grade A (90–100):** Hardened token meeting RFC 7519 best practices.
- **Grade B (75–89):** Minor non-critical hygiene flaws (e.g. missing issuer or audience).
- **Grade C (60–74):** Moderate operational risks (e.g. excessive lifespan or expired session).
- **Grade D (40–59):** Severe vulnerabilities (e.g. missing expiration or sensitive credentials).
- **Grade F (0–39):** Critical structural breaches (e.g. `alg:none` or cracked HMAC secret).

---

## 📦 Module Descriptions

- `server.js`: Core Express web server, routing, API dispatch, session history, and aggregate dashboard statistics.
- `analyzer.js`: Executes the 12 automated security audits, calculates deductions, and maps letter grades.
- `jwtUtils.js`: Performs safe Base64URL decoding, structure extraction, and rapid offline HMAC dictionary verification.
- `config.js`: Central configuration containing severity weights, 45+ dictionary attack secrets, sensitive regex patterns, and MITRE codes.
- `comparison.js`: Deep differential comparison engine detecting identity shifts, privilege escalations, and metadata changes.
- `tamperingLab.js`: Educational payload manipulation sandbox generating altered tokens and explaining signature verification rejection.
- `scoring.js`: Calculates Shannon entropy for secrets and builds the 4-Pillar Security Profile (Authentication, Claims, Cryptography, Lifetime).
- `recommendations.js`: Rule-based recommendation engine offering remediation advice, score recovery checklists, and hardened token generation.
- `learningData.js`: Educational repository housing 12 interactive vulnerability flashcards and 8 preconfigured attack scenarios.
- `reportGenerator.js`: Compiles comprehensive, print-ready HTML/PDF compliance audit reports with metadata and findings matrices.
- `test.js`: Comprehensive automated test runner containing 21 validation suites.

---

## 📡 REST API Documentation

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Serves the single-page web application UI. |
| `POST` | `/api/analyze` | Audits a single JWT (`{ token }`); returns score, grade, findings, profile, and improvement plan. |
| `POST` | `/api/analyze-bulk` | Audits an array of tokens simultaneously (`{ tokens: [...] }`). |
| `GET` | `/api/history` | Retrieves up to 20 recent analyses with truncated tokens for privacy. |
| `DELETE` | `/api/history` | Resets session analysis history. |
| `GET` | `/api/generate-test` | Generates 6 dynamic sample tokens with varying security postures. |
| `POST` | `/api/compare` | Compares two tokens (`{ tokenA, tokenB }`); detects role escalations and claim diffs. |
| `POST` | `/api/tamper` | Simulates payload modification (`{ originalToken, modifiedClaims }`); renders rejection flow. |
| `GET` | `/api/dashboard` | Returns aggregated session metrics, grade distributions, and historical score trajectory. |
| `POST` | `/api/secret-strength`| Evaluates secret key strength, Shannon entropy, and dictionary matches (`{ secret }`). |
| `GET` | `/api/learning` | Retrieves all 12 educational vulnerability guide cards. |
| `GET` | `/api/scenarios` | Retrieves the 8 preconfigured educational attack scenarios. |
| `POST` | `/api/scenarios/run` | Executes an attack scenario and compares findings against expected baselines. |
| `GET` | `/api/secure-example` | Generates a reference hardened JWT configuration. |
| `POST` | `/api/report` | Generates a standalone print-optimized audit report in HTML format. |
| `POST` | `/api/clear-all` | Executes complete privacy wipe: resets history, dashboard metrics, and caches. |

---

## ⚙️ Installation & Setup

### Prerequisites
- Node.js 20+ installed (`node -v`)
- npm installed (`npm -v`)

### Setup Commands
```bash
# 1. Clone or navigate to the project directory
cd vaultscan

# 2. Install dependencies (pure JS - zero native compilation required)
npm install
```

---

## 🚀 Running Instructions

```bash
# Start the web server
node server.js
```

Once launched, open your web browser and navigate to:
**`http://localhost:3000`**

---

## 🧪 Testing Suite & Verification

Execute the comprehensive automated test suite with:
```bash
npm test
```

### Test Output Verification:
```
========================================================
🛡️  VAULTSCAN COMPREHENSIVE AUTOMATED TEST SUITE
========================================================

  ✔ PASS: 1. Valid Hardened JWT (Score 100, Grade A)
  ✔ PASS: 2. Invalid & Malformed JWT (Graceful Error Handling)
  ✔ PASS: 3. Check 1: alg:none Detection (CRITICAL)
  ✔ PASS: 4. Check 2: Weak HS256 Secret (CRITICAL, MITRE T1110.002)
  ✔ PASS: 5. Check 3: Algorithm Confusion Warning (HIGH, MITRE T1550.001)
  ✔ PASS: 6. Check 4: Missing exp Claim (HIGH)
  ✔ PASS: 7. Check 5: Expired Token Detection (MEDIUM)
  ✔ PASS: 8. Check 6: Excessive Expiration > 24 Hours (MEDIUM)
  ✔ PASS: 9. Check 7: Sensitive Data in Payload (HIGH, MITRE T1552.001)
  ✔ PASS: 10. Check 8 & 9: Missing iss and aud Claims (LOW)
  ✔ PASS: 11. Check 10: kid Path Traversal (HIGH, MITRE T1083)
  ✔ PASS: 12. Check 11: Large Token Size > 4KB (LOW)
  ✔ PASS: 13. Check 12: External jku URL (HIGH, MITRE T1195)
  ✔ PASS: 14. JWT Comparison Engine (Detect Role Escalation & Claim Diffs)
  ✔ PASS: 15. JWT Tampering Simulator (Payload Alteration & Rejection Flow)
  ✔ PASS: 16. Secret Strength Analyzer (Entropy & Dictionary Match)
  ✔ PASS: 17. 4-Pillar Token Security Profile Builder
  ✔ PASS: 18. Recommendation & Score Improvement Engine
  ✔ PASS: 19. Attack Scenario Lab (Predefined Scenarios & Validation)
  ✔ PASS: 20. Security Report Generator (HTML/PDF Structure)
  ✔ PASS: 21. Edge Cases (Malformed Base64, Special Unicode, Empty inputs)

========================================================
RESULTS: 21 PASSED, 0 FAILED
========================================================

✅ ALL COMPREHENSIVE VAULTSCAN TESTS PASSED SUCCESSFULLY.
```

---

## 🖥️ User Interface Overview

- **Cyber Dark Aesthetic:** Monospace typography (JetBrains Mono), responsive layout, and glowing cyan accents (`#00d4ff`).
- **Interactive Conic Gauge:** Pure CSS circular gauge smoothly animating from 0 to 100.
- **Tabbed Experience:** Seamlessly toggle across Dashboard, Analyzer, Comparator, Tampering Lab, Security Lab, History, Learning Hub, and Reports without page reloads.
- **Copyable Remediation:** One-click clipboard copy for code fixes and configuration snippets.

---

## 🔒 Security Limitations & Boundaries

1. **Defensive & Educational Design:** VaultScan is strictly an audit and educational tool. It does not perform active network scanning, credential stuffing, or exploit deployment against third-party systems.
2. **Offline Inspection Semantics:** Pure structural inspection without the server secret verifies claim hygiene and format compliance, but cannot verify whether an untrusted token was signed with an unknown private key.
3. **Dictionary Cracking Boundaries:** The dictionary attack specifically tests against common shared passwords and development defaults; it is not intended to replace dedicated GPU cluster cracking (e.g. Hashcat).

---

## 🔮 Future Enhancements
- Integration of JSON Web Encryption (JWE) parsing and nested token inspection.
- Automated JWKS endpoint health and certificate chain revocation checking (CRL/OCSP).
- Exportable SARIF (Static Analysis Results Interchange Format) reports for CI/CD pipeline gating.
- Interactive token forging lab with browser-based WebCrypto key generation.

---

## 🎓 Conclusion
VaultScan addresses critical developer education gaps in token-based identity systems. By coupling automated vulnerability auditing with interactive defense sandboxes, VaultScan transforms abstract authentication vulnerabilities into tangible, actionable security knowledge.
