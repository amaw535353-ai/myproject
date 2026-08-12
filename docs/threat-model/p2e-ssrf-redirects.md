# P2-E — SSRF, DNS resolution, and redirect revalidation

## Security property

An agent-, model-, document-, or tool-controlled URL is never authorization to reach a network destination. The server owns the outbound policy. Before every connection, including every redirect hop, AegisDesk must validate the parsed URL, exact hostname allowlist, scheme/port restrictions, and the resolved destination addresses. Non-global addresses fail closed.

## Scope and safety

P2-E uses an **in-memory synthetic resolver and synthetic HTTP transport only**. It opens no sockets, performs no operating-system DNS, contacts no cloud metadata service, and targets no third-party system. Addresses such as `169.254.169.254` and `127.0.0.1` are labels inside deterministic fixtures used to classify forbidden destinations.

## Trust boundary

```text
untrusted URL
    |
    v
server-owned URL policy
    |  parse + exact allowlist + HTTPS/443
    |  resolve with deterministic resolver
    |  reject any non-global address
    v
synthetic transport
    |
    +--> response / redirect
             |
             +--> redirect target returns to the policy gate
```

The hardened fetcher passes the validated `connect_ip` directly to the transport. This models address pinning after policy resolution rather than allowing a lower layer to perform a second uncontrolled DNS lookup.

## Hardened policy

`UrlSecurityPolicy` applies these rules before each synthetic connection:

1. maximum URL length and no control characters;
2. HTTPS only;
3. no URL userinfo credentials;
4. no ambiguous backslash authority;
5. exact, case-normalized hostname allowlist;
6. default HTTPS port only;
7. deterministic DNS resolution must succeed;
8. **every** returned IP must be globally routable;
9. response byte budget;
10. redirect budget;
11. each redirect target is parsed, allowlisted, resolved, and checked again.

Checking all DNS answers matters because accepting a mixed public/private answer and selecting only the convenient public result leaves room for resolver/connection-layer disagreement. P2-E fails the entire target when any answer is non-global.

## Attack P2E-A1 — redirect to link-local destination

### Setup

The initial URL is `https://docs.aegisdesk.test/redirect-internal`. Its synthetic DNS answer is globally routable and the hostname is allowlisted. The route responds with a redirect to a synthetic link-local metadata address.

### Vulnerable behavior

The intentionally vulnerable fetcher checks only the initial hostname. It automatically follows the redirect without reapplying the allowlist or resolved-address policy. The synthetic transport therefore records a connection to the forbidden link-local destination.

### Hardened behavior

The hardened fetcher allows the initial public request, receives the redirect, constructs the next absolute URL, and sends it back through `UrlSecurityPolicy`. The redirect hostname is not allowlisted, so execution stops before a second transport call. No forbidden connection occurs.

## Attack P2E-A2 — allowlisted hostname resolves to loopback

### Setup

`rebind.aegisdesk.test` is intentionally present in the server allowlist to model a hostname whose DNS state has become unsafe. The deterministic resolver maps it to `127.0.0.1`.

### Vulnerable behavior

The vulnerable fetcher treats hostname membership as sufficient authorization and connects to the first resolved address without classifying it. The synthetic transport records a forbidden loopback connection.

### Hardened behavior

The hardened policy resolves the hostname before transport dispatch and rejects the non-global address. The synthetic transport records no request.

## Benign tasks

Two matched benign cases exercise usability:

- a direct allowlisted documentation fetch with a public DNS answer;
- a redirect from the documentation host to an allowlisted status host, where both DNS answers are public.

The hardened target is FPR `0/2` and SafeTaskRate `2/2`.

## Regression tests

Tests cover:

- exact HTTPS host acceptance;
- HTTP, userinfo, alternate ports, and non-allowlisted hosts rejected;
- loopback, private, link-local, IPv6 loopback, and mixed public/private DNS answers rejected;
- redirect targets revalidated before connection;
- redirect and response-size budgets;
- vulnerable link-local redirect reproduction;
- vulnerable private-resolution reproduction;
- hardened safe cross-allowlist redirect;
- deterministic P2-E ASR/FPR/SafeTaskRate delta.

## Evidence and metrics

`python -m evals.p2e_ssrf_redirects` records:

- code commit and dependency versions;
- deterministic attack/benign dataset hash;
- deterministic resolver/route fixture hash;
- policy versions;
- connection IP and public/forbidden classification;
- raw ASR/FPR/SafeTaskRate numerators and denominators.

Response bodies are not included in the evaluation report.

Expected fixed-set result:

- vulnerable ASR: `2/2 = 100%`;
- hardened ASR: `0/2 = 0%`;
- hardened FPR: `0/2 = 0%`;
- hardened SafeTaskRate: `2/2 = 100%`.

These values are regression evidence for the two deterministic attack classes only; they are not a general SSRF benchmark.

## Residual risk

This milestone deliberately does not implement a real HTTP client, proxy stack, TLS verification, system DNS, IPv4-mapped IPv6 handling across every runtime, DNS rebinding races in a live resolver, PAC files, environment proxies, connection pooling, or egress firewall rules. Before a production network tool is enabled, the same server-owned policy must be integrated with a real client in a way that prevents lower layers from re-resolving or bypassing the validated destination. Network-layer egress controls should remain independent defense in depth.
