# Mihomo rule supply-chain audit

Fail-closed gate in front of `openclash-rules`.

> Readable source for diffs. Real Mihomo for routing. Golden list as insurance.
> Policy Contract defines correctness. Only PASS publishes.
> Binary-only MRS without a reliable source is MODE_C: lower trust, never fake added/removed domains.

## Pipeline

```
download candidate
→ size/HTML validate (existing mirror script)
→ audit (this directory)
→ routing regression
→ PASS → force-push openclash-rules → jsDelivr purge
REVIEW / FAIL / exception / missing baseline / oracle error → BLOCK
```

Existing “校验成功” is not this gate. It only checks download + bytes + not-HTML.

## Trust modes

| Mode | When | Semantic diff |
|---|---|---|
| A | Published artifact is yaml/list/txt | AVAILABLE |
| B | MRS + sibling readable source (666OS `.txt`) | AVAILABLE on the text |
| C | MRS only (e.g. fakeip-filter) or txt missing | UNAVAILABLE — do not invent domain lists |

MRS decode via `mihomo convert-ruleset` is an **optional** probe. It must not upgrade trust.

## Oracle

Mihomo has **no** `POST /match` API (probed at runtime). Production oracle:

1. Isolated harness (`audit/harness.yaml`) with dummy DIRECT/REJECT groups
2. No airport subscription, no secrets
3. Probe host through mixed-port (timeouts expected)
4. Read `/connections` or logs for matched rule + policy
5. HTTP 200 is never used as correctness

Fixture oracle exists **only** for unit tests.

## Coverage boundary

Harness order follows `qingliangban-mihomo-fork-custom.yaml` among **mirrored** providers, plus a few inline DOMAIN-* lines from that config. Personal RULE-SETs (`de_*`, `us_paypal`, …) are not in this mirror and are not loaded.

## Commands

```bash
python -m unittest discover -s audit/tests -v

python audit/scripts/audit.py run \
  --audit-dir audit \
  --baseline /path/to/openclash-rules-baseline \
  --candidate /path/to/openclash-rules-candidate \
  --out audit/reports/audit-report.json \
  --fail-closed
```

`--oracle fixture` is test-only. CI uses `--oracle auto` (real kernel, fail closed).

Pinned Mihomo: `v1.19.15` (`audit/thresholds.yaml`).
