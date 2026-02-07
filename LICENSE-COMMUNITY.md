# AgentVerus Community License

Version 1.0 — February 2026

Copyright (c) 2026 AgentVerus

## Summary

The AgentVerus scanner engine is available under the [MIT License](./LICENSE-SCANNER.md).
The AgentVerus Trust Registry, API, badge system, and associated web services
("the Service") are available under the terms below.

---

## 1. Definitions

**"You"** means the individual or entity exercising rights under this license.

**"Annual Revenue"** means the total gross revenue of the legal entity (including
all subsidiaries and affiliates) that uses or integrates the Service, measured
over the most recent completed fiscal year.

**"Scanner"** means the AgentVerus skill scanning engine, analyzers, scoring
algorithm, CLI tool, and all source code in the `src/scanner/` directory and
related test fixtures. The Scanner is licensed separately under the MIT License.

**"Service"** means the AgentVerus Trust Registry, REST API, badge generation
system, certification flow, web interface, and all associated infrastructure
— excluding the Scanner.

**"Commercial Use"** means any use of the Service in connection with a product
or service that generates revenue, or by an entity with Annual Revenue exceeding
the Free Use Threshold.

**"Free Use Threshold"** means one million US dollars ($1,000,000) in Annual
Revenue.

---

## 2. Free Use Grant

You may use, access, and integrate the Service at no cost, without a commercial
license, provided that:

a. You are an individual using the Service for personal, educational, or
   non-commercial purposes; **or**

b. You are an entity (including sole proprietorships) with Annual Revenue
   **at or below** the Free Use Threshold; **or**

c. You are using the Service solely for open-source projects that are
   distributed under an OSI-approved license and do not directly generate
   revenue.

Under the Free Use Grant you receive:
- API access (rate-limited: 1,000 requests/day)
- Trust score lookups and scan submissions
- Basic badge embedding (with "Verified by AgentVerus" attribution)
- Public registry listing for scanned skills

---

## 3. Commercial License Required

A commercial license is required if:

a. Your Annual Revenue **exceeds** the Free Use Threshold; **or**

b. You wish to use the Service without attribution on badges; **or**

c. You require SLA guarantees, dedicated support, or custom integrations.

Commercial licenses are available at https://agentverus.ai/pricing or by
contacting licensing@agentverus.ai.

Commercial license tiers include:

| Tier | Annual Revenue | Includes |
|------|---------------|----------|
| **Growth** | $1M – $10M | 50,000 API requests/day, SLA 99.5%, badge without attribution, webhook notifications, email support |
| **Scale** | $10M – $100M | 500,000 API requests/day, SLA 99.9%, bulk scanning, priority support, custom badge branding |
| **Enterprise** | $100M+ | Unlimited API, SLA 99.95%, on-premise scanner option, dedicated support, compliance reports, audit trail, custom integrations |

---

## 4. Revenue Reporting

Entities using the Service under the Free Use Grant represent and warrant that
their Annual Revenue does not exceed the Free Use Threshold. AgentVerus reserves
the right to request reasonable verification of Annual Revenue. Failure to
respond within thirty (30) days of a verification request constitutes a breach
of this license.

---

## 5. Scanner License

The AgentVerus Scanner is licensed under the MIT License (see
[LICENSE-SCANNER.md](./LICENSE-SCANNER.md)). You may use the Scanner without
restriction, including for commercial purposes, regardless of revenue. This
Community License does not restrict the Scanner in any way.

---

## 6. Contributions

Contributions to the Scanner are accepted under the MIT License.
Contributions to the Service require a Contributor License Agreement (CLA).

---

## 7. No Warranty

THE SERVICE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED. AGENTVERUS SHALL NOT BE LIABLE FOR ANY DAMAGES ARISING FROM THE USE
OF THE SERVICE.

---

## 8. Termination

This license terminates automatically if You breach any of its terms. Upon
termination, You must cease all use of the Service. Termination does not
affect the MIT License grant for the Scanner.

---

## 9. Changes to This License

AgentVerus may publish updated versions of this license. Existing users may
continue under the version in effect when they first adopted the Service, or
adopt any later version at their discretion.

---

## Quick Reference

| Use Case | License Required | Cost |
|----------|-----------------|------|
| Individual / personal | No | Free |
| Company ≤ $1M revenue | No | Free |
| Open-source project | No | Free |
| Company $1M – $10M | Yes (Growth) | Contact sales |
| Company $10M – $100M | Yes (Scale) | Contact sales |
| Company $100M+ | Yes (Enterprise) | Contact sales |
| Scanner (any use) | MIT | Free forever |
