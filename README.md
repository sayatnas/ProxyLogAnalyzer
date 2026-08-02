# ProxyLogAnalyzer

Upload a web proxy log (Zscaler-style CSV) and get a SOC-analyst view of what's
in it: parsed events, anomalies flagged with a reason and a confidence score,
MITRE ATT&CK tags, a timeline, and an AI layer that verifies, ranks and
investigates the findings.

Built for the TENEX take-home exercise. Design decisions and trade-offs are in
[docs/DESIGN.md](docs/DESIGN.md).

There is a live deployment; the URL and demo credentials are shared
privately. Note it runs on free hosting, so the backend sleeps when idle and
the first request can take up to a minute.

## Stack

- React + TypeScript (Vite)
- Flask
- JWT auth (PyJWT), scrypt password hashing
- OpenAI Chat Completions for the AI layer

Analyses are held in memory keyed by upload id and scoped to the user who
uploaded them; the uploaded file on disk is the durable copy. No database:
the finding shape was still changing during the build, and a schema would have
been friction without buying anything a prototype needs. Findings and events
would go to Postgres in a real build, with raw logs staying on object storage.

## Running locally

Backend:

```
cd backend
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python app.py
```

Frontend (separate terminal):

```
cd frontend
npm install
npm run dev
```

Open http://localhost:5173 and log in with `analyst` / `analyst`.

Or `docker compose up` from the repo root, same URL, same login.

For the AI features, copy `.env.example` to `backend/.env` and put your OpenAI
key in it. Without a key everything still works; the AI panels degrade to
template output and say so.

## Example logs

`examples/sample_day.log` is a generated day of traffic for a small office:
~7,500 requests, a few malformed lines, and planted anomalies recorded in
`examples/sample_day.ground_truth.json` so you can check what the app should
find. Regenerate with `python generate_logs.py --seed 42` from `backend/`.

Planted: a request-rate spike to a coin miner, all-day beaconing from a service
account, a 192 MB upload to cloud storage, and one typosquat domain that no
statistical detector can catch (three quiet requests, only the name is wrong).
That last one is there to show what the AI sweep adds over the detectors.

## Tests

```
cd backend
.venv\Scripts\python -m pytest tests
```

Detection is evaluated against the ground truth file: every planted anomaly
must be found and nothing else may be flagged. The rest covers the parser,
the pseudonymizer (round trips, the regex collision cases), and tool schema
generation. The LLM paths are deliberately untested here; they are
nondeterministic and cost money, so they are constrained by validation code
at runtime instead.

## How detection works

Plain statistics, not ML. Each detector builds a per-entity baseline and flags
outliers: requests per minute per host (median/MAD z-score), upload volume per
user, and interval regularity for beaconing. Robust statistics matter here: on
the sample log the exfiltration scores z=4871 with median/MAD but only 2.8 with
mean/stdev, because the attacker's own traffic drags the mean. Thresholds are
constants at the top of `detectors.py` with the reasoning next to them.

Detection is deterministic and testable against the ground truth file. The
model never decides what is anomalous.

## The AI layer

Three pieces, all on-demand buttons, all bounded agent loops over the same
read-only tools (query events, profile a domain, profile a host, rarity
overview). Tool schemas are generated from the Python function signatures, so
adding a tool is one function plus one registry line.

**AI Summarize** runs a triage agent: it verifies each finding with the tools
before ranking (a small burst to a malware-category domain outranks a bigger
one to a CDN), reports verified cross-finding links, recommends actions, and
then sweeps a rarity overview for suspicious activity the detectors did not
flag. Sweep results render as leads, clearly separated from findings, because
they are model judgement, not statistics.

**AI Investigate** digs into one finding: the model chooses which tools to
call, round by round, and returns a short assessment in a fixed
verdict/evidence/gaps format. Every tool call it made is shown in an
expandable trace so you can check the claims against the data it actually saw.

Guardrails, since model output can't be trusted blindly:

- usernames and internal IPs are pseudonymized (`user-3`, `host-7`) before
  anything reaches the API and mapped back on the way out; domains stay
  visible because their names are the evidence
- every response is validated in code: allowed assessment values, capped and
  deduplicated leads, malformed JSON falls back to a template
- tools are closures over one upload's records, capped in rows and steps, so
  the model cannot reach other users' data or run up an unbounded bill

I built this with Claude Code as a pair programmer, mainly for scaffolding and
prototyping.
