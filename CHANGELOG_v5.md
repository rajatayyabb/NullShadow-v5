# NullShadow v5.0 — Changelog & Test Commands

Built **additively** on v4.0. No existing v4 module was rewritten; only
`db.py`, `findings_extract.py`, `risk_score.py`, `exploit_refs.py`, `main.py`,
`mcp_server.py` and `dashboard.py` were **extended**. IoT options [23][24] are
hidden from the menu (files kept).

Run everything from the repo root with the venv active:
`python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt`

---

## Section 0.5 — Findings quality fix
- `modules/intel/findings_extract.py`: open-port findings now read
  product/version/service from nmap and build specific titles like
  `Port 443/tcp https — nginx 1.18.0` instead of generic text.
- **Test:** `python3 modules/intel/findings_extract.py` (import check) — or run a
  real scan: `python3 main.py` → [26] Auto Full Recon → [36] Findings.

## DB migrations (null_db/db.py)
New tables: `threat_intel_cache`, `sentinel_alerts`, `remediation_stats`.
New `findings` columns: `remediation_id`, `remediation_given_at`. All additive
(safe `ALTER TABLE` with `OperationalError` guard). New helper methods for each.
- **Test:** `python3 modules/intel/time_machine.py` (exercises the migrations).

## Phase A — Odysseus integration  (VERIFIED against the real Odysseus source)
The brief's Phase A had three details that did not match the actual Odysseus
build you sent; the integration is corrected to the real contract:

| Brief said | Real Odysseus (verified in source) |
|---|---|
| port 7000 | **7011** host port (`APP_PORT`); container listens on 7000 internally |
| `POST /servers` + JSON | `POST /api/mcp/servers` + **form-encoded** (`routes/mcp/mcp_routes.py`) |
| "Bearer admin API token" | admin **session cookie** `odysseus_session` via `POST /api/auth/login`, **or** `X-Odysseus-Internal-Token` header, **or** `AUTH_ENABLED=false` (`core/middleware.py: require_admin`) |

- `docker/register_nullshadow_mcp.py` — rewritten to the real contract. Supports
  three auth modes: `--username/--password` (login→cookie), `--internal-token`
  (`ODYSSEUS_INTERNAL_TOKEN`), or `--no-auth` (`AUTH_ENABLED=false`). Posts
  form-encoded `name/transport/command/args/env` with `args`&`env` as JSON strings.
  **Tested end-to-end against a mock enforcing the exact endpoint/cookie/form contract.**
- `docker-compose.v5.yml` + `Dockerfile` — core + dashboard (8077) + ollama.
- **A.4 visual rebrand:** Odysseus UI lives in `static/` (`index.html`, `login.html`,
  `app.js`, `css/`) and `frontend/src/` — **not** a `templates/` dir. Replace the
  "Odysseus" brand string there and apply the `#0d0d0d`/`#cc0000` theme AFTER
  registration works end-to-end.
- **Test (on your host, needs Docker):**
  ```
  docker compose -f docker-compose.v5.yml up -d
  git clone https://github.com/pewdiepie-archdaemon/odysseus.git nullshadow_ui
  cd nullshadow_ui && cp .env.example .env && docker compose up -d --build && cd ..
  # open http://localhost:7011 , create the admin account, then:
  python3 docker/register_nullshadow_mcp.py \
      --odysseus-url http://localhost:7011 --username admin --password '<pw>'
  ```

## Phase B — Security Posture Time Machine
- `modules/intel/time_machine.py` · menu **[42]** · dashboard `/timemachine` · MCP `exposure_analysis`.
- **Test:** `python3 modules/intel/time_machine.py`

## Phase C — Real-time Threat Intel (CISA KEV + OTX + ThreatFox)
- `modules/intel/threat_feeds.py` · menu **[43]** · dashboard `/threatintel` · MCP `threat_intel_check`.
  KEV match forces finding → CRITICAL (`actively_exploited=True`).
- **Test (offline logic):** `python3 modules/intel/threat_feeds.py`

## Phase D — Scan Engine (Nikto / WhatWeb / Dirb / HashCrack / SQLi)
- `modules/pentesting/scan_engine.py` · menu **[37]**–**[41]**.
  Missing Kali tools degrade gracefully; hash crack has a 5-step chain ending in a
  pure-Python fallback (never errors). SQLi is DETECTION-ONLY.
- **Test (offline paths):** `python3 modules/pentesting/scan_engine.py`
- **Test (full, on Kali):** `python3 main.py` → [37] Full Web Scan → a target you own.

## Phase E — AI System Pentesting (OWASP LLM Top 10)
- `modules/pentesting/ai_pentest.py` + `data/prompt_injection_patterns.txt` ·
  menu **[44]** · dashboard route via findings · MCP tool `ai_pentest` (through recon).
  Detection-only benign canary probes — no jailbreaks, no harmful extraction.
- **Test:** `python3 modules/pentesting/ai_pentest.py`

## Phase F — AI Attack Narrative (Purple Team)
- `modules/intel/attack_narrative.py` · menu **[45]** · MCP `generate_attack_narrative`.
  Constrained AI prompt + deterministic rule-based fallback. No exploit code.
- **Test:** `python3 modules/intel/attack_narrative.py`

## Phase G — Cognitive Attack Prediction
- `modules/intel/attack_prediction.py` · menu **[46]** · dashboard `/prediction` · MCP `predict_exploitation`.
  Models NVD→CISA-KEV time-to-weaponization; tech-matched to the target.
- **Test:** `python3 modules/intel/attack_prediction.py`

## Phase H — Security DNA (breach pattern matching)
- `modules/intel/security_dna.py` + `data/breach_patterns.json` · menu **[47]** ·
  dashboard `/dna` · MCP `dna_analysis`.
- **Test:** `python3 modules/intel/security_dna.py`

## Phase I — Sentinel Mode (autonomous CVE watcher)
- `modules/intel/sentinel.py` · menu **[48]** · dashboard `/sentinel` · MCP `sentinel_status`.
  Daemon thread polls NVD recent feed; ntfy.sh push on tech-stack match.
- **Test:** `python3 modules/intel/sentinel.py`

## Phase J — Compliance Evidence Generator
- `modules/compliance/` (`compliance_mapper.py`, `evidence_generator.py`,
  `data/framework_controls.json`) · menu **[49]** · dashboard `/compliance` · MCP `compliance_report`.
  ISO 27001 / NIST CSF 2.0 / PCI DSS v4.0 / OWASP → audit PDF from real scans.
- **Test:** `python3 modules/compliance/evidence_generator.py` (writes a PDF to reports/)

## Phase K — Self-Healing Remediation Verification
- `modules/intel/remediation_tracker.py` · menu **[51]** · dashboard `/effectiveness`.
  Tracks per-category effectiveness; gives a *different* follow-up when a fix didn't take.
- **Test:** `python3 modules/intel/remediation_tracker.py`

## Phase L — Security Debt Forecasting
- `forecast_posture_trend()` added to `modules/intel/risk_score.py` · menu **[50]** · MCP `forecast_posture`.
  Least-squares projection; **refuses** with <10 runs (no fabricated trend).
- **Test:** `python3 modules/intel/risk_score.py`

## Phase M — Dashboard visual upgrade
- `dashboard.py`: nav bar, KPI count-up cards, Chart.js animations, and 7 new
  routes: `/timemachine /threatintel /prediction /dna /compliance /sentinel /effectiveness`.
- **Test:** `python3 dashboard.py` → open http://127.0.0.1:8077

## MCP server (mcp_server.py)
Added 8 tools: `threat_intel_check, exposure_analysis, generate_attack_narrative,
predict_exploitation, dna_analysis, compliance_report, forecast_posture, sentinel_status`.
- **Test:** `python3 mcp_server.py` (stdio) and call from Claude Desktop / Odysseus.

---

### One-shot sanity check (no Kali tools / no network needed)
```
python3 modules/intel/time_machine.py
python3 modules/intel/security_dna.py
python3 modules/intel/attack_narrative.py
python3 modules/intel/remediation_tracker.py
python3 modules/compliance/evidence_generator.py
python3 modules/pentesting/scan_engine.py
python3 -c "import ast; ast.parse(open('main.py').read()); ast.parse(open('dashboard.py').read()); ast.parse(open('mcp_server.py').read()); print('entrypoints parse OK')"
```

### Needs YOUR Kali box / network (written defensively, not fully testable here)
- Phase A Docker + Odysseus stack.
- Phase D real Kali tools (nikto/whatweb/dirb/hashcat/john) — missing-tool paths verified.
- Live CISA KEV / OTX / ThreatFox / NVD-recent feeds (cache + graceful-failure verified).
