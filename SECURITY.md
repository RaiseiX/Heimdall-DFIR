# Security policy

Heimdall handles forensic evidence, credentials and investigation data. Please report security problems privately so they can be assessed before technical details become public.

## Supported versions

Heimdall does not have a stable, tagged release line yet. Until the release process is unified, security fixes target the current `main` branch only.

| Code line | Security support |
| --- | --- |
| Current `main` branch | Supported |
| Older commits and untagged snapshots | No routine backports; update to the current branch |

This policy will be revised when the project starts publishing supported release branches.

## Report a vulnerability

Use [GitHub's private vulnerability reporting form](https://github.com/RaiseiX/Heimdall-DFIR/security/advisories/new).

Do not open a public issue, post the report on Discord, or include sensitive case data in a discussion. If a large or sensitive attachment is needed, start with the private report and agree on a transfer method with the maintainer.

Include what you can from the following list:

- a short description of the vulnerability and its likely impact;
- the affected commit, branch or installation date;
- the deployment conditions and privileges required to reproduce it;
- minimal reproduction steps or a proof of concept using synthetic data;
- relevant logs with tokens, credentials, personal data and evidence content removed;
- any known workaround or suggested fix;
- whether the issue is already public or appears to be actively exploited.

Reports do not need to be perfectly complete. A clear private warning is better than waiting for a polished advisory.

## What to expect

The project aims to:

- acknowledge a new report within five calendar days;
- provide an initial assessment within ten calendar days;
- send an update at least every fourteen days while the report remains open;
- coordinate a fix and disclosure date with the reporter when the issue is confirmed.

These are response targets, not a guarantee that every fix can be released within that period. Parser dependencies, container images and upstream projects may require additional coordination. Reports involving active exploitation or immediate evidence exposure take priority.

The maintainer will normally close a report as one of the following:

- accepted, with remediation and disclosure work tracked in the private advisory;
- accepted as an upstream issue, with coordination moved to the affected project;
- not reproducible, with the missing conditions explained;
- not a security vulnerability, with the reason documented privately;
- duplicate of an existing private or public report.

There is currently no paid bug-bounty programme. Credit will be included in the advisory if the reporter wants it.

## Scope

Examples of issues that should be reported privately include:

- authentication or role bypass;
- cross-case data access, IDOR or broken case isolation;
- exposure of evidence, credentials, tokens or integration keys;
- SQL injection, command injection, path traversal, unsafe archive extraction, XSS or SSRF;
- upload or parser behaviour that can execute untrusted content outside the intended boundary;
- tampering that bypasses audit, legal-hold or evidence-integrity controls;
- privilege escalation through containers, the Docker socket or service configuration;
- a dependency vulnerability that is reachable through Heimdall and has a concrete impact.

Ordinary bugs, feature requests, documentation mistakes and findings without a plausible security impact can use the public issue tracker.

## Research guidelines

Security research should use an installation and accounts you own or are explicitly authorised to test.

- Use synthetic evidence and test identities.
- Access only the minimum data needed to demonstrate the issue.
- Stop if testing reaches third-party data or infrastructure.
- Do not leave persistence, disrupt shared services, exfiltrate data or degrade another user's investigation.
- Do not upload live malware to an instance you do not fully control.
- Keep vulnerability details private until a disclosure date has been agreed or the advisory has been published.

The project will not pursue action against good-faith research that follows these guidelines and makes a reasonable effort to avoid privacy violations, data loss and service disruption. This statement cannot authorise testing of third-party systems or override their terms and policies.

## Disclosure and advisories

For a confirmed vulnerability, the preferred process is:

1. reproduce and assess the impact privately;
2. prepare a fix and regression test;
3. agree on disclosure timing with the reporter;
4. publish a GitHub Security Advisory and remediation instructions;
5. request a CVE when the impact and affected distribution justify one.

The usual disclosure target is within 90 days of a confirmed report. It may be shorter for active exploitation or extended by agreement when an upstream dependency is involved.

Public advisories will avoid real investigation data and will state the affected code, fixed code and available mitigations as precisely as possible.
