# Runbook: Issuing the First Paid License

> Owner-only document. Walks through the full path: payment → issue →
> deliver → verify → track. All secrets live in `~/.secrets/talus/`
> and are **never** pasted into chat, issues, or the repo.

---

## 0. One-time setup checklist

- [ ] Signing key exists: `~/.secrets/talus/license-keys/signing_key.json`
      (created by `talus-keygen init`; if you ever re-run `init`, **all
      previous keys are void** — see SECURITY.md rotation runbook).
- [ ] Activation server is up: `scripts/health-check.sh` → `✓ healthy`.
- [ ] Keygen is built: `cd license-keygen && cargo build --release`.
- [ ] Payment channel is chosen (Gumroad / Lemon Squeezy / manual transfer).
- [ ] Prices decided **outside** this repo (see `docs/pricing-tiers.md`).

Secrets map:

| Secret | Location | Used for |
|---|---|---|
| Ed25519 private key | `~/.secrets/talus/license-keys/signing_key.json` | signing licenses |
| Admin token | `~/.secrets/talus/admin_token` | `scripts/revoke-license.sh`, `scripts/list-activations.sh` |
| Cloudflare API token | `~/.cloudflare_token` | deploying the worker |

---

## 1. Receive payment

Two options:

### Option A — manual (fine for the first sale)

1. Customer pays via bank transfer / PayPal / Stripe payment link.
2. You confirm the money arrived.

### Option B — automated webhook (later, optional)

Lemon Squeezy / Gumroad can call a webhook on order completion. To automate
issuing, add a small admin endpoint (`/api/v1/admin/issue`) that accepts a
signed webhook (verify the platform's HMAC signature header) and shells the
issuing logic. Until that exists, issuing is a one-line manual step —
honestly fine for the first handful of sales. Do **not** wire the webhook to
anything that would require putting the signing key on the server; issue
locally, upload nothing.

---

## 2. Decide license parameters

From the purchase record:

| Parameter | Flag | Example |
|---|---|---|
| Organization | `--org` | `"Acme Corp"` |
| Term | `--expires` | `2027-09-17` (omit = perpetual) |
| Seats | `--seats` | `5` |
| Managed nodes | `--max-nodes` | `0` = unlimited |
| Tier | `--tier` | `enterprise` |

## 3. Issue the license

```bash
./scripts/issue-license.sh --org "Acme Corp" --seats 5 --expires 2027-09-17
```

Output (locally only):

```
═══════════════════════════════════════════════════════════
  LICENSE KEY GENERATED
═══════════════════════════════════════════════════════════
  License ID:    TALUS-1234-ABCD-EF01
  ...
  │  LICENSE KEY                                        │
  └─────────────────────────────────────────────────────┘
```

The registry is appended at
`~/.secrets/talus/license-keys/issued_licenses.json` (0600, outside any
repository). **Copy the license key** — the full one-liner between the box
borders.

## 4. Deliver to the customer

Email template:

```
Subject: Your Talus Process Monitor Enterprise license

Hi <name>,

Thank you for your purchase! Your license key:

<KEY>

Activate it with:

    talus license activate <KEY>

Full activation guide: https://github.com/BartoszOsiej/talus-process-monitor/blob/master/docs/customer-activation-guide.md

License details:
  License ID:  TALUS-XXXX-XXXX-XXXX
  Seats:       5
  Expires:     2027-09-17

If anything doesn't work, reply to this email.

Best,
Bartosz
```

Send the key **and** keep the order record (invoice no., amount, date,
license ID) in your private ledger — amounts never go into the repo.

## 5. Sanity-check the delivered key

From the repo root (uses the offline registry, not the server):

```bash
./license-keygen/target/release/talus-keygen verify "<KEY>"
```

Expect `✓ License key is VALID` with the right License ID and tier.

## 6. Watch the activation land

After the customer runs `talus license activate <KEY>`, check seats:

```bash
./scripts/list-activations.sh TALUS-XXXX-XXXX-XXXX
```

Expected: one row — their `machine_id`, hostname, `seat_index: 1`.

## 7. Ongoing operations

| Task | Command |
|---|---|
| List issued licenses | `talus-keygen list` |
| Check server health | `./scripts/health-check.sh` |
| List who activated | `./scripts/list-activations.sh <ID>` |
| Refund / piracy → revoke | `./scripts/revoke-license.sh <ID> "reason"` |
| Free a stuck seat | `revoke-license.sh` (frees all seats) then re-issue a fresh key |

Revocation notes:

- Revoking removes all activations for that license; customers must get a
  replacement key if it was a mistake.
- Keys revoked **before** their first activation are held in the
  `revocations` table, so a leaked-but-never-used key is also dead on arrival.

---

## Escalation paths

- **Customer can't activate (seat limit, no old machine):** verify purchase,
  then `revoke-license.sh` + re-issue a new key with identical parameters.
- **Suspected key leak:** revoke, re-issue, note the old ID in the private
  ledger; do not publish the leaked ID.
- **Signing key compromise:** follow the rotation runbook in SECURITY.md —
  all keys become void; re-issue for paying customers free of charge.
