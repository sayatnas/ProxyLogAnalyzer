# ProxyLogAnalyzer

Upload a web proxy log (Zscaler-style CSV) and get a SOC-analyst view of it:

- parsed events, charts, timeline
- anomalies with reasons, confidence scores, and MITRE ATT&CK tags
- an AI layer that verifies, ranks, and investigates the findings

Built for the TENEX take-home exercise.

Live deployment exists, URL and credentials shared privately. Free hosting,
so the first request after idle can take up to a minute.

## Stack

- React + TypeScript (Vite), Flask, JWT auth with scrypt hashing, OpenAI
  Chat Completions
- No database: analyses live in memory keyed by upload id, scoped to their
  owner, uploaded file on disk as the durable copy, avoids schema friction
  at prototype stage
- A real build would need Postgres plus object storage for raw logs

## Running locally

1. AI features need a key: copy `.env.example` (repo root) to `backend/.env`
   and add your OpenAI key. Without one the app still works, AI panels
   degrade to template output and say so
2. Backend:
   ```
   cd backend
   python -m venv .venv
   .venv\Scripts\pip install -r requirements.txt
   .venv\Scripts\python app.py
   ```
3. Frontend (separate terminal):
   ```
   cd frontend
   npm install
   npm run dev
   ```
4. Open http://localhost:5173, log in with `analyst` / `analyst`, click
   "analyze the included example log" (or upload `examples/sample_day.log`)

Or `docker compose up` from the repo root, same URL and login, key in a root
`.env` or shell environment.

## Example logs

- `examples/sample_day.log`: a generated office day, ~7,500 requests, a few
  malformed lines. Planted anomalies, recorded in
  `examples/sample_day.ground_truth.json`:
  - request-rate spike to a coin miner
  - all-day beaconing from a service account
  - 192 MB upload to cloud storage
  - a user with 65% of their requests blocked
  - a single overnight hit to an unknown domain
  - a typosquat domain no statistical detector can catch (three quiet
    requests, only the name is wrong), there to show what the AI sweep adds
- `examples/sample_small.log`: ten quiet rows plus two malformed lines, for
  parser behaviour. Expect 2 skipped lines and zero findings
- Regenerate: `python generate_logs.py --seed 42` from `backend/`

## Tests

```
cd backend
.venv\Scripts\python -m pytest tests
```

- Detection is evaluated against the ground truth: every planted anomaly
  must be found and nothing else flagged
- Also covered: parser, pseudonymizer round trips and regex collisions, tool
  schema generation
- LLM paths are deliberately untested: nondeterministic and priced per call,
  so they are constrained by validation code at runtime instead

## How detection works

- Runs statistical algorithms over per-entity baselines and flags outliers
- Detectors: requests per minute per host (median/MAD z-score), upload
  volume per user, interval regularity for beaconing, blocked-request ratio
  per user, and rare uncategorized destinations
- Thresholds are constants at the top of `detectors.py`, reasoning beside them
- Detection is deterministic and testable. The model never decides what is
  anomalous

## The AI layer

On-demand buttons, all bounded agent loops over the same read-only tools
(query events, profile a domain or host, rarity overview). Tool schemas are
generated from the Python function signatures, so a new tool is one function
plus one registry line.

**AI Summarize**, a triage agent:

- verifies each finding with the tools before ranking (a small burst to a
  malware-category domain outranks a bigger one to a CDN)
- reports verified cross-finding links and recommended actions
- sweeps the rarity overview for activity the detectors did not flag,
  rendered as leads, visually separate from findings, because they are model
  judgement, not statistics

**AI Investigate**, per finding:

- the model chooses its own tool calls, round by round
- returns a fixed assessment/evidence/gaps note
- every tool call is shown in an expandable trace, so claims can be checked
  against the data the model actually saw

Guardrails, since model output can't be trusted blindly:

- usernames and internal IPs are pseudonymized (`user-3`, `host-7`) before
  anything reaches the API and mapped back on return. Domains stay visible
  because their names are the evidence
- every response is validated in code: allowed assessment values, capped and
  deduplicated leads, malformed JSON falls back to a template
- tools are closures over one upload's records, capped in rows and steps

Built with Claude Code as a pair programmer, mainly for scaffolding and
prototyping.
