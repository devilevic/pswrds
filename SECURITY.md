# Security policy

pswrds is a zero-knowledge password manager: vaults are encrypted in the browser and the server stores only encrypted, fixed-size slots. The design, threat model and known limitations are described at https://pswrds.com/security.html.

## Reporting a vulnerability

Please email **info@pswrds.com** with a description and, if possible, steps to reproduce. Please don't open a public issue for security problems.

- We reply within a few days and fix confirmed issues as quickly as we can.
- We credit reporters on the security page if they'd like.
- When testing, don't access other people's vaults or disrupt the service. Use the demo (https://pswrds.com/#demo), your own test vaults, or a local copy of this repository.

## Scope

In scope: the web app (`src/pswrds.html`), the server API (`server/api.php`) and the static pages. Out of scope: the hosting provider and the payment processor (NOWPayments).
