# AccessCheck API — Full Product Specification

**Product Name:** AccessCheck API  
**Version:** 1.0  
**Category:** Developer Tools / Web Compliance  
**Distribution:** RapidAPI Marketplace + Direct  
**Last Updated:** March 2026

---

## Table of Contents

1. [Product Vision](#1-product-vision)
2. [What the API Does (Plain English)](#2-what-the-api-does)
3. [Core Concepts & Terminology](#3-core-concepts--terminology)
4. [Input Modes](#4-input-modes)
5. [Endpoints — Full Reference](#5-endpoints--full-reference)
6. [Request Parameters](#6-request-parameters)
7. [Response Schema](#7-response-schema)
8. [Severity & Impact Levels](#8-severity--impact-levels)
9. [Standards & Rule Coverage](#9-standards--rule-coverage)
10. [Compliance Score System](#10-compliance-score-system)
11. [AI Remediation Layer](#11-ai-remediation-layer)
12. [Asynchronous Scan Flow (for full-site crawls)](#12-asynchronous-scan-flow)
13. [Webhooks](#13-webhooks)
14. [Rate Limits & Quotas](#14-rate-limits--quotas)
15. [Pricing Tiers](#15-pricing-tiers)
16. [Error Handling](#16-error-handling)
17. [Legal & Disclaimer Requirements](#17-legal--disclaimer-requirements)
18. [Suggested Tech Stack](#18-suggested-tech-stack)
19. [Competitive Differentiation](#19-competitive-differentiation)
20. [Roadmap](#20-roadmap)

---

## 1. Product Vision

AccessCheck API is a **developer-first REST API** that lets any application programmatically audit a web page, HTML snippet, or entire website for accessibility violations across WCAG 2.0, 2.1, 2.2, ADA, Section 508, and the European Accessibility Act (EAA).

The core promise is simple:

> Send us a URL or HTML. Get back a structured JSON report of every accessibility violation, its severity, which WCAG success criterion it violates, which DOM element caused it, and an AI-generated fix suggestion — in under 10 seconds.

**Who it is for:**

- Web agencies running accessibility audits for clients
- CMS and website builder platforms (Webflow, Wix, WordPress plugin developers)
- CI/CD pipelines that need automated accessibility regression testing
- Compliance SaaS tools embedding accessibility scoring
- In-house dev teams building accessible products
- LegalTech / ADA lawsuit prevention platforms

---

## 2. What the API Does

At the highest level, the API does five things:

1. **Renders** the target page (full JavaScript execution via headless browser) or parses submitted HTML
2. **Audits** the rendered DOM against a comprehensive accessibility rule set
3. **Classifies** each issue by standard (WCAG level), severity, and affected disability category
4. **Scores** the page with a 0–100 compliance score, broken down by POUR principle (Perceivable, Operable, Understandable, Robust)
5. **Explains** each violation in plain English and suggests a concrete code fix using an LLM layer

The API does **not** claim to guarantee full ADA or WCAG compliance — automated scanning catches approximately 40–57% of all WCAG issues. The API makes this explicit in every response with a `coverage_disclaimer` field, protecting both the API provider and the developer's end clients from legal overreach.

---

## 3. Core Concepts & Terminology

| Term | Definition |
|---|---|
| **Scan** | A single audit run against one URL or one HTML payload |
| **Violation** | A confirmed accessibility failure — an element that definitively breaks a rule |
| **Incomplete** | An issue axe-core flagged but could not confirm automatically — requires human review |
| **Pass** | A rule that was checked and passed on this page |
| **Inapplicable** | A rule that did not apply to this page (e.g., video rules on a page with no video) |
| **WCAG Level A** | The minimum accessibility baseline — must-fix issues |
| **WCAG Level AA** | The standard legal compliance target in most jurisdictions |
| **WCAG Level AAA** | The highest level — aspirational, not legally required in most cases |
| **Impact** | How severely the issue affects users with disabilities (critical / serious / moderate / minor) |
| **POUR** | The four WCAG principles: Perceivable, Operable, Understandable, Robust |
| **Success Criterion (SC)** | A specific testable requirement in the WCAG spec (e.g., SC 1.1.1: Non-text Content) |
| **Job** | An async scan job created for multi-page or full-site audits |

---

## 4. Input Modes

The API accepts three different input modes. The developer chooses based on their use case.

### Mode A — URL Scan (Most Common)
The developer passes a public URL. The API spins up a headless browser (Playwright + Chromium), fully renders the page including JavaScript, waits for the DOM to stabilize, then runs the audit. This is the most accurate method because it reflects what a real user's browser actually renders.

**Best for:** Agency audits, monitoring dashboards, one-off page checks.

**Limitations:** The URL must be publicly accessible. Pages behind authentication require Mode B. Render time adds 3–8 seconds per page.

### Mode B — HTML Payload Scan
The developer sends raw HTML in the request body. The API parses the HTML statically without executing JavaScript. This is the fastest mode (sub-second response) and works well for server-rendered templates, email templates, and pages behind login walls.

**Best for:** CI/CD pipelines, template validation before deployment, static site generators.

**Limitations:** Because JavaScript is not executed, dynamic content (modal dialogs, single-page app views, lazy-loaded components) will not be audited. The response will include a `static_scan_warning` flag indicating this.

### Mode C — Authenticated URL Scan *(Pro and above)*
The developer provides a URL plus authentication credentials (cookies, Bearer token, or a login sequence). The API handles authentication before rendering the page. This allows auditing pages behind login walls — dashboards, checkout flows, account settings — which are frequently the most legally problematic pages.

**Best for:** E-commerce checkout, SaaS dashboards, healthcare portals.

**Limitations:** Requires careful credential handling. Credentials are never logged or stored. Each authenticated scan counts as 3 standard scans against quota.

---

## 5. Endpoints — Full Reference

All endpoints are under the base URL:

```
https://api.accesscheck.io/v1
```

On RapidAPI, the base URL becomes the RapidAPI proxy URL, and authentication is handled via the `X-RapidAPI-Key` header.

---

### `POST /scan`
**Synchronous page scan.** Run an accessibility audit on a single URL or HTML payload. Returns results immediately. Best for single-page, on-demand checks. Times out at 30 seconds.

---

### `POST /scan/batch`
**Batch synchronous scan.** Submit up to 10 URLs or HTML payloads in a single request. The API scans them in parallel and returns all results in one response. Useful for scanning all pages in a small site or all templates in a design system.

---

### `POST /jobs`
**Create an async scan job.** For full-site crawls (up to 500 pages), submit a root URL and crawl configuration. Returns a `job_id` immediately. The API crawls and audits the site in the background. Poll `/jobs/{job_id}` or receive results via webhook when complete.

---

### `GET /jobs/{job_id}`
**Get job status and results.** Returns the current status of an async job (`queued`, `running`, `complete`, `failed`) and, when complete, the full results for every page scanned.

---

### `DELETE /jobs/{job_id}`
**Cancel a running job.** Stops an in-progress crawl. Partial results are returned for pages already scanned.

---

### `GET /rules`
**List all available rules.** Returns the full catalogue of accessibility rules the API can test, including which WCAG success criterion each rule maps to, which standards it covers (WCAG 2.0/2.1/2.2, Section 508, EAA), and the rule's description.

---

### `GET /rules/{rule_id}`
**Get a specific rule.** Returns full documentation for a single rule including what it tests, why it matters, common causes, and a general fix guide.

---

### `GET /standards`
**List supported standards and their rule counts.** Returns a summary of each compliance standard the API covers (WCAG 2.0 A, WCAG 2.0 AA, WCAG 2.1 A, WCAG 2.1 AA, WCAG 2.2 A, WCAG 2.2 AA, Section 508, EAA EN 301 549).

---

### `POST /diff`
**Compare two scans.** Submit two `scan_id` values (or two HTML payloads) and receive a diff report showing which violations were introduced, fixed, or unchanged between the two. Useful for tracking accessibility progress over a sprint or before/after a deployment.

---

### `GET /usage`
**Get current API usage.** Returns the authenticated user's scan count, quota remaining, reset date, and current plan tier.

---

## 6. Request Parameters

This section documents every parameter accepted by the primary `POST /scan` endpoint. Batch and job endpoints inherit the same scan-level parameters plus their own controls.

### Required (one of the following)

| Parameter | Type | Description |
|---|---|---|
| `url` | string | A fully qualified public URL to audit. Must include `https://` or `http://`. |
| `html` | string | Raw HTML string to audit statically. Must be a complete HTML document (with `<html>` and `<body>` tags) or a fragment. |

### Scan Behavior

| Parameter | Type | Default | Description |
|---|---|---|---|
| `standard` | string or array | `"wcag22aa"` | Which standard(s) to audit against. Accepts a single value or an array. Options: `wcag20a`, `wcag20aa`, `wcag21a`, `wcag21aa`, `wcag22a`, `wcag22aa`, `wcag22aaa`, `section508`, `eaa`. |
| `wait_for` | string | `"load"` | When to start the audit after the page begins loading. Options: `load` (page load event fires), `networkidle` (no network activity for 500ms), `selector` (wait for a specific CSS selector to appear — requires `wait_selector` parameter). Use `networkidle` for SPAs. |
| `wait_selector` | string | null | A CSS selector the API waits for before auditing. Used when specific dynamic content must be present. Example: `"#main-content"`. |
| `wait_timeout_ms` | integer | `10000` | Maximum milliseconds to wait for the page to reach the `wait_for` condition. If exceeded, the scan proceeds on the current DOM state. Max: `30000`. |
| `viewport` | object | `{width: 1280, height: 800}` | Browser viewport dimensions. Accepts `width` and `height` as integers. Use `{width: 375, height: 812}` to simulate a mobile screen. |
| `user_agent` | string | Chrome 121 | Custom user agent string. Useful for testing how a page serves different content to different browsers. |
| `exclude_selectors` | array | `[]` | CSS selectors for elements to exclude from the audit. Useful for skipping known third-party widget violations (e.g., a chat widget you don't control). Example: `["#intercom-widget", ".third-party-ad"]`. |
| `include_selectors` | array | `[]` | Restrict the audit to only the specified elements and their descendants. Useful for scanning a specific component. If empty, the entire DOM is scanned. |
| `run_only` | array | null | Limit the audit to only specific rule IDs. If null, all rules for the selected standard(s) run. Example: `["color-contrast", "image-alt", "label"]`. |
| `disable_rules` | array | `[]` | Rule IDs to skip. Useful when certain rules produce known false positives in your stack. |

### Response Control

| Parameter | Type | Default | Description |
|---|---|---|---|
| `include_passes` | boolean | `false` | Whether to include rules that passed in the response. Passing rules are excluded by default to keep responses compact. Set to `true` for a full compliance evidence report. |
| `include_inapplicable` | boolean | `false` | Whether to include rules that were inapplicable to this page. |
| `include_incomplete` | boolean | `true` | Whether to include items that need manual review. Recommended to keep `true`. |
| `include_remediation` | boolean | `true` | Whether to include AI-generated fix suggestions for each violation. Set to `false` to reduce response size and latency if you only need the violation data. |
| `remediation_detail` | string | `"standard"` | Level of fix detail in AI suggestions. Options: `brief` (one sentence), `standard` (explanation + fix), `verbose` (explanation + fix + code example + resources). `verbose` adds 1–2 seconds of latency. |
| `locale` | string | `"en"` | Language for violation descriptions and remediation text. Supported: `en`, `fr`, `de`, `es`, `pt`, `ja`, `ko`, `zh`. |
| `screenshot` | boolean | `false` | Whether to include a base64-encoded screenshot of the page in the response. Useful for visual audit reports. Adds ~1 second and significant response size. Pro tier and above. |

### Authentication (Mode C only)

| Parameter | Type | Description |
|---|---|---|
| `auth.type` | string | Authentication method. Options: `cookie`, `bearer`, `basic`, `login_flow`. |
| `auth.cookies` | array | Array of cookie objects (`name`, `value`, `domain`) to inject before loading the page. |
| `auth.token` | string | Bearer token to include in request headers. |
| `auth.login_flow` | object | A sequence of steps (navigate, fill, click, wait) to perform a form-based login before auditing. |

---

## 7. Response Schema

Every successful scan returns a JSON object with the following top-level structure.

### Top-Level Response Object

| Field | Type | Description |
|---|---|---|
| `scan_id` | string (UUID) | Unique identifier for this scan. Use to reference it in `/diff` calls or support requests. |
| `url` | string | The URL that was scanned (or `null` if an HTML payload was submitted). |
| `scan_mode` | string | `"url"`, `"html"`, or `"authenticated_url"`. |
| `standard` | array | The standards that were audited against. |
| `scanned_at` | string (ISO 8601) | Timestamp of when the scan completed. |
| `duration_ms` | integer | How long the scan took in milliseconds. |
| `dom_snapshot` | string | A hash of the DOM that was audited, for reproducibility. Not the full DOM. |
| `score` | object | The compliance score object. See Section 10. |
| `summary` | object | Counts of violations, incomplete items, passes, and inapplicable rules. |
| `violations` | array | Array of violation objects. The core payload. See below. |
| `incomplete` | array | Array of items needing manual review. Same schema as `violations`. |
| `passes` | array | Array of rules that passed (only included if `include_passes: true`). |
| `inapplicable` | array | Array of inapplicable rules (only included if `include_inapplicable: true`). |
| `coverage_disclaimer` | string | Boilerplate disclaimer that automated testing covers ~57% of WCAG issues and does not constitute a full legal compliance audit. Always included. Cannot be suppressed. |
| `meta` | object | Request echo and API version info. |

---

### Summary Object

```
summary
├── violations_count          integer   Total number of violations found
├── violations_by_impact      object    { critical, serious, moderate, minor }
├── incomplete_count          integer   Items needing manual review
├── passes_count              integer   Rules that passed
├── inapplicable_count        integer   Rules that did not apply
├── elements_affected         integer   Total DOM elements with at least one violation
└── new_in_wcag22             integer   Violations specific to WCAG 2.2 (not in 2.1)
```

---

### Violation Object

Each item in the `violations` array has this structure:

```
violation
├── id                        string    Rule ID (e.g., "color-contrast", "image-alt")
├── description               string    Human-readable description of what the rule checks
├── help                      string    Short explanation of why this matters
├── help_url                  string    Link to Deque's documentation for this rule
├── impact                    string    "critical" | "serious" | "moderate" | "minor"
├── wcag_criteria             array     List of WCAG success criteria this rule maps to
│   └── [each criterion]
│       ├── sc_number         string    e.g., "1.4.3"
│       ├── sc_name           string    e.g., "Contrast (Minimum)"
│       ├── level             string    "A" | "AA" | "AAA"
│       └── wcag_version      string    "2.0" | "2.1" | "2.2"
├── standards                 array     Standards this violation affects (WCAG, Section 508, EAA)
├── disability_categories     array     Which users are most affected: "visual", "motor", "cognitive", "hearing", "speech"
├── nodes                     array     The specific DOM elements that triggered this violation
│   └── [each node]
│       ├── html              string    The serialized outer HTML of the offending element
│       ├── target            array     CSS selector path to the element (e.g., ["#main > form > label"])
│       ├── xpath             string    XPath to the element
│       ├── failure_summary   string    Explanation of exactly why this element fails the rule
│       ├── any               array     Fix options where at least one must be satisfied
│       ├── all               array     Fix requirements that must all be satisfied
│       └── none              array     Conditions that must not exist
├── remediation               object    AI-generated fix. Present if include_remediation: true
│   ├── plain_english         string    What's wrong, explained simply
│   ├── fix_instruction       string    What the developer needs to do
│   ├── code_example          string    A corrected HTML/CSS snippet (verbose mode only)
│   ├── effort_estimate       string    "low" | "medium" | "high" — how hard this is to fix
│   ├── auto_fixable          boolean   Whether this can be fixed programmatically vs. requiring human judgment
│   └── resources             array     Links to WCAG understanding docs and techniques (verbose mode only)
└── tags                      array     Internal rule tags (e.g., "wcag2a", "wcag22aa", "best-practice")
```

---

### Score Object

See Section 10 for full scoring methodology. The score object structure:

```
score
├── overall                   integer   0–100 overall compliance score
├── grade                     string    "A+" | "A" | "B" | "C" | "D" | "F"
├── perceivable               integer   0–100 score for POUR Principle 1
├── operable                  integer   0–100 score for POUR Principle 2
├── understandable            integer   0–100 score for POUR Principle 3
├── robust                    integer   0–100 score for POUR Principle 4
├── critical_issues           integer   Number of critical-impact violations (must be 0 for any passing score)
└── wcag22_delta              integer   Score improvement or regression vs. WCAG 2.1 AA baseline
```

---

## 8. Severity & Impact Levels

Every violation is tagged with one of four impact levels, inherited from axe-core's classification system.

| Level | Meaning | User Experience | Legal Risk |
|---|---|---|---|
| **Critical** | The element is completely unusable for some users | A screen reader user literally cannot access this content at all. A keyboard-only user is completely blocked. | Highest — these are the violations most cited in ADA lawsuits. |
| **Serious** | Major barrier — workarounds may exist but are significantly degraded | The content is technically accessible but the experience is substantially worse than for sighted/mouse users. | High — regularly cited in demand letters. |
| **Moderate** | The user is inconvenienced but can still access the content | The experience is suboptimal. Power users with assistive tech may work around it. | Medium — creates a pattern of inaccessibility if widespread. |
| **Minor** | A best-practice violation with minimal impact | Mostly invisible to users. More of a polish/quality issue. | Low on its own, but can signal systemic neglect. |

> **Product Decision:** In the compliance score, Critical violations are weighted 10x, Serious 5x, Moderate 2x, and Minor 1x. This ensures a page with one critical violation scores significantly lower than a page with twenty minor ones.

---

## 9. Standards & Rule Coverage

Axe-core's rules library is constantly updated and covers WCAG 2.0, 2.1, and 2.2 at levels A, AA, and AAA, and also adheres to rules outlined in Section 508, EN 301 549, RGAA, and ADA.

The API wraps axe-core and exposes all of these as selectable standards via the `standard` parameter.

### Standard Tags Available

| Standard Tag | Full Name | Jurisdiction |
|---|---|---|
| `wcag20a` | WCAG 2.0 Level A | Global |
| `wcag20aa` | WCAG 2.0 Level AA | Global (legacy) |
| `wcag21a` | WCAG 2.1 Level A | EU Web Accessibility Directive baseline |
| `wcag21aa` | WCAG 2.1 Level AA | Current global default; US ADA standard |
| `wcag22a` | WCAG 2.2 Level A | Current W3C recommendation (2023+) |
| `wcag22aa` | WCAG 2.2 Level AA | **API default.** Current best-practice baseline as of 2026 |
| `wcag22aaa` | WCAG 2.2 Level AAA | Aspirational maximum compliance |
| `section508` | Section 508 (Revised 2018) | US Federal agencies, federal contractors |
| `eaa` | EN 301 549 / EAA | European Accessibility Act (enforced June 2025) |
| `best-practice` | Axe Best Practices | Not a legal standard — dev quality guide |

Developers can pass multiple standards as an array. The API deduplicates overlapping rules and flags which standards each violation affects.

### WCAG 2.2 — New Rules Not in 2.1

WCAG 2.2 adds 9 new success criteria including Focus Appearance for keyboard focus indicators, Dragging Movements ensuring all actions can be completed without drag gestures, and Target Size requiring tap/click targets to be at least 24×24 CSS pixels.

The API specifically tags violations that are new in WCAG 2.2 (not present in 2.1) with `new_in_wcag22: true` on the violation object, helping teams understand their 2.1→2.2 migration gap.

### Key Rules Tested (Non-exhaustive)

The following illustrates the breadth of what gets checked. Axe-core has rules for WCAG 2.0, 2.1, and 2.2 on levels A, AA, and AAA, as well as best practices including ensuring every page has an H1 heading and avoiding ARIA attribute gotchas where attributes get silently ignored.

**Images & Media**
- All images have meaningful alt text (SC 1.1.1)
- Decorative images are marked as presentational
- Videos have captions (SC 1.2.2)
- Audio has transcripts (SC 1.2.1)

**Color & Contrast**
- Text meets minimum contrast ratio of 4.5:1 (SC 1.4.3)
- Large text meets 3:1 ratio (SC 1.4.3)
- UI components and graphical elements meet 3:1 (SC 1.4.11)
- Color is not used as the sole means of conveying information (SC 1.4.1)

**Forms & Inputs**
- Every form input has an associated label (SC 1.3.1, 4.1.2)
- Required fields are communicated to assistive tech (SC 3.3.2)
- Error messages are programmatically associated with their inputs (SC 3.3.1)
- Autocomplete attributes are valid (SC 1.3.5)

**Navigation & Structure**
- Page has a meaningful `<title>` (SC 2.4.2)
- Heading hierarchy is logical (no skipped levels) (Best Practice)
- Landmark regions exist and are not duplicated (SC 1.3.6)
- Skip navigation link is present (SC 2.4.1)

**Keyboard & Focus**
- Every interactive element is keyboard focusable (SC 2.1.1)
- Focus order is logical (SC 2.4.3)
- Focus is visible and meets WCAG 2.2 minimum appearance (SC 2.4.11)
- No keyboard traps (SC 2.1.2)
- Touch targets meet 24×24px minimum (SC 2.5.8 — WCAG 2.2 new)

**ARIA & Semantics**
- ARIA roles are valid (SC 4.1.2)
- ARIA attributes are valid for their elements (SC 4.1.2)
- Elements have accessible names (SC 4.1.2)
- ARIA IDs are unique and non-empty (SC 4.1.1)

**Language & Internationalization**
- `<html lang>` attribute is set and valid (SC 3.1.1)
- Language changes within a page are marked (SC 3.1.2)

---

## 10. Compliance Score System

The API generates a 0–100 compliance score for every scan. This score is opinionated by design — it exists to give developers and non-technical stakeholders a digestible signal, not as a legal compliance certification.

### Scoring Formula

The score is calculated as:

```
Base Score = 100

For each violation:
  Deduction = Impact Weight × Frequency Factor × Rule Importance Factor

  Impact Weights:
    Critical  = 10 points per affected element (capped at 40 per rule)
    Serious   =  5 points per affected element (capped at 20 per rule)
    Moderate  =  2 points per affected element (capped at 10 per rule)
    Minor     =  1 point  per affected element (capped at  5 per rule)

Final Score = max(0, Base Score − sum of all deductions)
```

### Grade Thresholds

| Score | Grade | Interpretation |
|---|---|---|
| 95–100 | A+ | Excellent. Minimal automated issues. Ready for human audit. |
| 85–94 | A | Strong. Address remaining issues to reach A+. |
| 70–84 | B | Good foundation. Moderate issues exist that affect real users. |
| 55–69 | C | Significant issues. Multiple user groups are impacted. Action required. |
| 40–54 | D | Serious accessibility barriers. Legal exposure risk. |
| 0–39 | F | Fundamental failures. High legal risk. Urgent remediation needed. |

> **Hard Rule:** If any Critical impact violations are present, the score is capped at 60 (grade D maximum), regardless of how high the arithmetic score would otherwise be. A single "keyboard trap" that blocks all keyboard users cannot coexist with a grade A.

### POUR Breakdown

The score is also broken down by the four WCAG principles:

- **Perceivable** — Can users perceive all content? (alt text, captions, contrast)
- **Operable** — Can users operate all functionality? (keyboard nav, focus, timing)
- **Understandable** — Is the content and UI clear? (language, consistent navigation, error messages)
- **Robust** — Does the content work with assistive technologies? (valid ARIA, semantic HTML)

Each principle score follows the same 0–100 formula, restricted to rules in that principle's category.

---

## 11. AI Remediation Layer

Every violation optionally includes an AI-generated `remediation` object. This is the API's primary differentiator over a raw axe-core wrapper.

### How It Works

The remediation layer takes three inputs:
1. The rule that was violated (its description and fix guidance from axe-core)
2. The actual offending HTML element from the page
3. The surrounding DOM context (parent element, sibling elements) for relevance

These are passed to an LLM prompt (Claude Sonnet or equivalent) that generates a fix specifically tailored to the actual code on the page — not a generic "add alt text to your images" message.

### Remediation Detail Levels

**Brief** — One clear instruction sentence.
> *"Add an alt attribute describing the image content to the `<img>` element on line 47."*

**Standard** (default) — Why it matters + what to do.
> *"This image has no alt attribute, making it invisible to screen readers. Users relying on assistive technology have no way to understand what the image conveys. Add an `alt` attribute with a concise description of what the image shows. If the image is decorative, use `alt=""` to explicitly mark it as presentational."*

**Verbose** — Full explanation + corrected code snippet + links.
> Standard explanation, plus a corrected HTML snippet showing the element with the fix applied, an effort estimate, and links to the relevant WCAG Understanding document and applicable WCAG techniques.

### Auto-Fixable Flag

Each remediation object includes `auto_fixable: true/false`. This signals whether the fix can be applied programmatically (e.g., adding `aria-label` to a button, adding `lang` to the HTML element) vs. requiring human judgment (e.g., writing meaningful alt text for a complex chart).

This flag is useful for clients who want to build an automated fix-application layer on top of the API.

---

## 12. Asynchronous Scan Flow

For full-site crawls, the API uses an async job model to handle large workloads without timing out.

### Job Lifecycle

```
1. Developer POSTs to /jobs with root URL + crawl config
   └── API immediately returns { job_id, status: "queued", estimated_pages: N }

2. API begins crawling from the root URL
   └── Discovers links, respects robots.txt, stays within the configured scope
   └── Audits each discovered page
   └── Status moves to "running", progress is available via GET /jobs/{id}

3. On completion:
   └── Status moves to "complete"
   └── Full results available via GET /jobs/{id}
   └── If webhook configured: HTTP POST sent to the webhook URL with results

4. Results available for 30 days, then archived
```

### Crawl Configuration Options

| Parameter | Description |
|---|---|
| `max_pages` | Maximum pages to crawl. Default 50. Max 500 (Business tier), unlimited (Enterprise). |
| `max_depth` | Maximum link depth from the root URL. Default 3. |
| `include_patterns` | URL patterns (glob or regex) to include in the crawl. |
| `exclude_patterns` | URL patterns to exclude (e.g., `"/blog/*"`, `"/admin/*"`). |
| `respect_robots_txt` | Whether to obey the site's robots.txt. Default `true`. |
| `same_domain_only` | Whether to follow links to external domains. Default `true`. |
| `scan_options` | The same scan options as the synchronous `POST /scan` endpoint, applied to every page. |
| `concurrency` | How many pages to scan simultaneously. Default 3. Max 10 (Enterprise only). |

---

## 13. Webhooks

Webhooks allow the API to push results to the developer's server when an async job completes, rather than requiring polling.

### Configuration

Webhooks are configured per API key in the developer dashboard. Each webhook has:
- A target URL (must respond with HTTP 200 within 5 seconds)
- An optional HMAC secret for signature verification
- A list of events to subscribe to (`job.complete`, `job.failed`, `scan.complete` for monitoring mode)

### Webhook Payload

The webhook POST body contains the same structure as `GET /jobs/{job_id}` — a full results object — plus a `webhook_event` field indicating which event triggered the delivery.

### Reliability

Webhook deliveries are retried up to 5 times with exponential backoff (1s, 2s, 4s, 8s, 16s) if the target server fails to respond with HTTP 200. After 5 failures, the delivery is marked as failed and logged in the developer dashboard.

---

## 14. Rate Limits & Quotas

Rate limiting operates on two dimensions: **requests per minute** (burst protection) and **scans per month** (quota/billing).

### Requests Per Minute (RPM)

| Tier | Synchronous Scans RPM | Batch Requests RPM | Job Creates RPM |
|---|---|---|---|
| Free | 2 | 0 | 0 |
| Hobby | 10 | 2 | 1 |
| Pro | 30 | 10 | 5 |
| Business | 60 | 20 | 10 |
| Enterprise | Unlimited | Unlimited | Unlimited |

When a rate limit is exceeded, the API returns `HTTP 429 Too Many Requests` with a `Retry-After` header indicating when the limit resets.

### Monthly Scan Quotas

Quota consumption rules:
- Standard URL or HTML scan = **1 scan credit**
- Authenticated URL scan = **3 scan credits**
- Batch scan = **1 credit per URL in the batch**
- Async job = **1 credit per page crawled and scanned**
- Screenshot = **+1 credit per scan**
- `/diff` endpoint = **1 credit** (no new scanning)

---

## 15. Pricing Tiers

Tiers are designed to create a clear upgrade path from indie developer → agency → platform.

### Free Tier
- **Price:** $0/month
- **Scans:** 20/month
- **Standards:** WCAG 2.1 AA only
- **Features:** URL + HTML scan, basic violations only, no remediation, no batch, no async jobs
- **Purpose:** Exploration and integration testing

### Hobby — $19/month
- **Scans:** 300/month (overage: $0.08/scan)
- **Standards:** WCAG 2.0, 2.1, 2.2 (all levels)
- **Features:** Full violations + incomplete, AI remediation (standard detail), Section 508
- **Purpose:** Freelancers and personal projects

### Pro — $79/month
- **Scans:** 2,500/month (overage: $0.04/scan)
- **Standards:** All standards including EAA
- **Features:** Everything in Hobby + batch scans (10 URLs), authenticated scans, screenshots, async jobs (up to 50 pages), webhook support, POUR breakdown scores, API key management
- **Purpose:** Agencies running client audits, SaaS tools embedding compliance checks

### Business — $299/month
- **Scans:** 15,000/month (overage: $0.02/scan)
- **Standards:** All
- **Features:** Everything in Pro + full-site crawl up to 500 pages, diff endpoint, priority queue for jobs, verbose remediation with code examples, team API key management, CSV/PDF report export endpoint, white-label report branding
- **Purpose:** Compliance SaaS platforms, large agencies, CMS builders

### Enterprise — Custom pricing
- **Scans:** Unlimited
- **Standards:** All + custom rule sets
- **Features:** Everything in Business + SLA (99.9% uptime), dedicated infrastructure, custom data residency (EU/US), SSO, audit logs, IP allowlisting, custom integration support
- **Purpose:** Website builders (Wix, Webflow plugin), large enterprise compliance teams, government contractors

---

## 16. Error Handling

All errors return a consistent JSON envelope:

```json
{
  "error": {
    "code": "RENDER_TIMEOUT",
    "message": "The page did not reach a stable state within the configured timeout.",
    "docs_url": "https://docs.accesscheck.io/errors/RENDER_TIMEOUT",
    "request_id": "req_01hx...",
    "retryable": true
  }
}
```

### Error Code Reference

| HTTP Status | Error Code | Meaning |
|---|---|---|
| 400 | `INVALID_URL` | The URL is malformed or unreachable. |
| 400 | `INVALID_HTML` | The HTML payload could not be parsed. |
| 400 | `INVALID_STANDARD` | An unrecognised standard tag was passed. |
| 400 | `SELECTOR_NOT_FOUND` | The `wait_selector` CSS selector was not found within the timeout period. |
| 401 | `UNAUTHORIZED` | API key is missing or invalid. |
| 403 | `PLAN_FEATURE_NOT_AVAILABLE` | The requested feature requires a higher tier. |
| 429 | `RATE_LIMIT_EXCEEDED` | Requests per minute limit hit. |
| 429 | `QUOTA_EXCEEDED` | Monthly scan quota exhausted. |
| 502 | `RENDER_FAILED` | The headless browser encountered an error rendering the page. |
| 504 | `RENDER_TIMEOUT` | The page did not stabilise within `wait_timeout_ms`. |
| 500 | `INTERNAL_ERROR` | An unexpected server error. Automatically retried internally once. |

All errors include a `retryable` boolean indicating whether the same request is likely to succeed on retry.

---

## 17. Legal & Disclaimer Requirements

This is non-negotiable for any accessibility compliance product, given the FTC fine against accessiBe.

### Mandatory Response Disclaimer

Every scan response **always** includes the `coverage_disclaimer` field. It cannot be suppressed by any API parameter. The text reads:

> *"This automated scan detects approximately 40–57% of potential WCAG accessibility issues. A passing score or low violation count does not constitute legal ADA or WCAG compliance. Automated testing cannot evaluate subjective criteria, dynamic interactions, or issues requiring human judgment. A complete compliance assessment requires manual expert review and user testing with people who have disabilities. This API is a development and auditing tool, not a legal certification service."*

### What Developers Must Not Do

The API terms of service explicitly prohibit developers from:
- Claiming the API output constitutes a legal compliance audit or certification
- Representing automated scan results as a substitute for a full human accessibility audit
- Using the API output as evidence in legal proceedings without supplementary manual audit
- Misrepresenting a scan score as "compliant" when violations are present

These restrictions must be passed through to end users in the developer's application terms.

---

## 18. Suggested Tech Stack

This is the recommended build path for an indie developer or small team.

### Core Engine
- **axe-core** (MPL 2.0 license) — the accessibility rule engine. Axe-core has been downloaded 3 billion+ times and is actively supported by Deque Systems. Free, well-maintained, zero licensing cost.
- **Playwright** (Apache 2.0) — headless browser for URL rendering. Supports Chromium, Firefox, WebKit. Handles SPAs, JS-heavy pages, and lazy-loaded content.
- **`@axe-core/playwright`** — official integration package connecting the two.

### API Layer
- **Node.js + Fastify** (or Python + FastAPI) — high-performance REST API framework
- **BullMQ + Redis** — async job queue for crawl jobs and webhook delivery retries
- **PostgreSQL** — scan results storage, job state, API key management

### AI Remediation
- **Claude Sonnet via Anthropic API** (or GPT-4o) — generate the remediation text and code examples. Call only when `include_remediation: true` to control costs. Cache remediation for identical violations on identical element patterns.

### Infrastructure
- **Docker** — containerise the Playwright browser + axe runner
- **Railway, Render, or Fly.io** — cost-effective hosting for the initial launch
- **Cloudflare Workers** — edge API key validation and rate limiting before requests hit your servers
- **AWS S3 or Cloudflare R2** — store screenshots and async job results

### Estimated Monthly COGS at 2,500 scans (Pro tier)
| Item | Est. Cost |
|---|---|
| Playwright browser instances (2 workers) | ~$30 |
| Redis (BullMQ) | ~$15 |
| PostgreSQL | ~$15 |
| AI remediation (Claude API, ~500 calls with caching) | ~$5 |
| Bandwidth + storage | ~$10 |
| **Total COGS** | **~$75/month** |

At $79/month Pro pricing, the margin per customer is roughly **$4 at break-even** — but at 10 Pro customers, COGS scales sub-linearly (shared infrastructure), making margins strong at volume.

---

## 19. Competitive Differentiation

### vs. accessiBe / UserWay (Overlay tools)
These are JavaScript overlays injected onto end-user websites. They are **not APIs**. Developers cannot use them programmatically. They are also legally controversial (multiple lawsuits claim they don't actually make sites compliant). AccessCheck is a developer tool, not an overlay — completely different market position.

### vs. Deque axe DevTools Pro
Deque's paid product is a browser extension and CI plugin, not a REST API. It requires developers to install tooling in their local environment. AccessCheck is infrastructure — callable from anywhere, embeddable in any product.

### vs. WAVE API (WebAIM)
WAVE has an API but it is limited: returns HTML report output rather than structured JSON, has no AI remediation, no scoring, no WCAG 2.2 support, no async jobs, and is priced per-page (not tiered SaaS). AccessCheck's structured JSON, scoring system, and remediation layer are significant upgrades.

### vs. Existing RapidAPI Providers
The current accessibility APIs on RapidAPI have 1–2 star reviews citing broken authentication, outdated rule sets (still on WCAG 2.1), no documentation, and abandoned maintenance. The competitive bar is genuinely low. A well-documented, actively maintained API with current WCAG 2.2 rules will stand out immediately.

### The Core Moat
1. **WCAG 2.2 currency** — most tools lag behind on new success criteria
2. **AI remediation** — no competitor gives you element-specific fix instructions in JSON
3. **Reliability** — 99.9% uptime SLA vs. abandoned RapidAPI providers
4. **Structured JSON** — machine-readable output designed for embedding, not just human reading
5. **Developer documentation** — interactive examples, SDKs, Postman collection from day one

---

## 20. Roadmap

### Phase 1 — MVP (Weeks 1–3)
- `POST /scan` with URL and HTML modes
- WCAG 2.1 AA + WCAG 2.2 AA rule sets
- Standard remediation (no AI — just axe-core's built-in fix summaries)
- Compliance score and POUR breakdown
- Free, Hobby, and Pro tiers
- Ship to RapidAPI

### Phase 2 — Differentiation (Weeks 4–8)
- AI remediation layer (Claude API integration)
- `POST /scan/batch` endpoint
- `GET /rules` and `GET /rules/{id}` endpoints
- Authenticated scan mode (cookie + bearer)
- Webhook support
- Section 508 and EAA standards

### Phase 3 — Platform (Months 3–4)
- `POST /jobs` async crawl engine
- `POST /diff` comparison endpoint
- Business tier launch
- CSV/PDF report export
- White-label branding for reports
- JavaScript SDK (`npm install accesscheck`)

### Phase 4 — Enterprise (Month 5+)
- Custom rule set support
- EU data residency option
- SSO and audit logs
- Figma plugin (audit designs before they become code)
- VS Code extension (scan the file currently open)
- Slack / GitHub Actions integrations

---

*AccessCheck API Specification v1.0 — March 2026*  
*This document is a product specification, not a legal compliance guide.*
