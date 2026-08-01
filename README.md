# ProxyLogAnalyzer

Upload a web proxy log (Zscaler-style) and get a SOC-analyst view of what's in it:
parsed events, anomalies flagged with a reason and a confidence score, MITRE ATT&CK
tags, and a short AI-written summary of what happened.

Built for the TENEX take-home exercise.

## Stack

- React + TypeScript (Vite)
- Flask
- PostgreSQL

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

Then open http://localhost:5173.

## AI usage

The app uses an LLM in exactly one place: turning already-computed findings into a
short analyst-style summary. Detection itself is plain statistics (per-entity
baselines and z-scores), not ML. It has to be explainable, cheap, and reproducible,
and an LLM is none of those per-event.

Raw log lines are never sent to the model, only aggregated findings. Two reasons:
log data is sensitive and shouldn't leave the system, and log content is
attacker-controlled text, so pasting it into a prompt is an injection risk.

I built this with Claude Code as a pair programmer, mainly for scaffolding and
prototyping.
