# Talus Pricing Tiers (structure — no amounts)

> Pricing **amounts** are set by the owner. This document fixes only the
> **structure**: what each tier contains, and which dimensions drive the
> price of an Enterprise license. Keep it free of numbers.

## Tiers

### Community — free, MIT-licensed
For individuals, homelabs and evaluation.

| Included | Not included |
|---|---|
| TUI dashboard (7 panels) | Web dashboard & REST API |
| Plain-text & JSON output | Auto-kill (EDR response mode) |
| Real-time eBPF monitoring | Kafka streaming |
| Ransomware detection alerts | ClickHouse analytics |
| Community support (GitHub issues) | MemGraph process graphs |
| | C FFI library |
| | Priority support |

### Enterprise — paid, per this licensing system
For teams and organizations that need response, integration and support.

Everything in Community, plus:

| Feature | Notes |
|---|---|
| Web dashboard & REST API | TLS, WebSocket stream, metrics |
| Auto-kill (EDR response mode) | Automatic process termination on alerts |
| Kafka streaming | lz4-compressed event stream |
| ClickHouse analytics | Long-term batch storage |
| MemGraph process graphs | Process relationship analytics |
| C FFI library | Embed Talus in other products |
| Priority support channel | Direct email to the maintainer |

## Price dimensions (owner decides values)

| Dimension | Values | Effect on price |
|---|---|---|
| Term | perpetual · 1 year · 3 year | longer term → higher price |
| Seats (machines) | 1 · 5 · 10 · unlimited | more seats → higher price |
| Managed nodes (`max_nodes`) | 1 · 10 · 0 (unlimited) | more nodes → higher price |
| Support level | best-effort · business hours · 48h SLA | higher SLA → higher price |
| Organization | individual · team · enterprise | volume discounts possible |

## Recommended starter bundles (structure only)

- **Single-seat, 1 year** — evaluation by a small team.
- **5 seats, perpetual** — small org standard.
- **Unlimited seats + unlimited nodes, perpetual, 48h SLA** — enterprise-wide.

## Where to set the actual amounts

1. Decide amounts for each dimension above.
2. Fill them in on the sales page / payment link (Gumroad, Lemon Squeezy…).
3. Do **not** commit amounts into this repository — this file stays structural.
