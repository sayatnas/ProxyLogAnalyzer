"""AI layer.

  summarize_findings()  one call, no tools, runs automatically on upload
  investigate_finding() bounded tool loop, runs when an analyst asks

"""
import inspect
import json
import logging
import os
import types
from typing import Literal, Union, get_args, get_origin, get_type_hints

log = logging.getLogger(__name__)

MODEL = os.environ.get("OPENAI_MODEL", "gpt-5.4-mini")
MAX_AGENT_STEPS = 10

try:
    from openai import OpenAI
    _client = OpenAI() if os.environ.get("OPENAI_API_KEY") else None
except ImportError:
    _client = None


def enabled() -> bool:
    return _client is not None


# Layer 1: summary

SUMMARY_PROMPT = """You are assisting a SOC analyst triaging one proxy log file.
You are given pre-computed statistical findings. Write a triage summary.

Rules:
- Use ONLY the findings provided. Never invent IP addresses, domains, users,
  times or numbers that do not appear in the input.
- Refer to entities exactly as given.
- Do not speculate about attacker identity or attribution.
- If the findings do not support a judgement, use "inconclusive".
- Recommended actions must be investigative steps an analyst can take today.
- Write for a SOC analyst mid-shift: telegraphic fragments, entity and numbers
  first, no filler words. "10.0.1.11: 60 req/min at 10:30, baseline 1.5" not
  "The host 10.0.1.11 generated a large number of requests".

Return ONLY JSON matching:
{
  "assessment": "benign" | "suspicious" | "malicious" | "inconclusive",
  "summary": "1-2 tight sentences: what happened, worst first",
  "key_observations": ["one fact each, entity first, fragment style"],
  "correlations": ["entities appearing in multiple findings, or a note that none do"],
  "recommended_actions": ["imperative fragments, most urgent first"]
}"""

ASSESSMENTS = {"benign", "suspicious", "malicious", "inconclusive"}


def _fallback_summary(findings: list[dict]) -> dict:
    """Template summary used when the model is unavailable or returns garbage.

    The app must work with the LLM down, so its absence degrades the page
    rather than breaking it.
    """
    if not findings:
        return {
            "assessment": "benign",
            "summary": "No anomalies were detected in this log.",
            "key_observations": [],
            "correlations": [],
            "recommended_actions": [],
            "generated_by": "fallback",
        }
    high = [f for f in findings if f["confidence"] >= 0.8]
    return {
        "assessment": "suspicious" if high else "inconclusive",
        "summary": (f"{len(findings)} anomalies detected, {len(high)} at high confidence. "
                    "AI summary unavailable; findings below are unaffected."),
        "key_observations": [f"{f['entity']}: {f['reason']}" for f in findings[:5]],
        "correlations": [],
        "recommended_actions": ["Review each finding and pivot into its supporting events."],
        "generated_by": "fallback",
    }


def summarize_findings(stats: dict, findings: list[dict], pseudo=None) -> dict:
    if not enabled():
        return _fallback_summary(findings)

    scrub = pseudo.scrub if pseudo else (lambda t: t)
    unscrub = pseudo.unscrub if pseudo else (lambda t: t)

    payload = {
        "stats": stats,
        "findings": [
            {k: f[k] for k in ("detector", "entity", "mitre", "confidence",
                               "reason", "first_seen", "last_seen") if k in f}
            for f in findings
        ],
    }

    try:
        response = _client.chat.completions.create(
            model=MODEL,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": SUMMARY_PROMPT},
                {"role": "user", "content": scrub(json.dumps(payload))},
            ],
        )
        data = json.loads(unscrub(response.choices[0].message.content))
    except Exception as exc:
        log.warning("summary generation failed: %s", exc)
        return _fallback_summary(findings)

    # Never trust the output: validate before it reaches the UI.
    if data.get("assessment") not in ASSESSMENTS or not data.get("summary"):
        log.warning("summary failed validation: %s", data)
        return _fallback_summary(findings)

    data["generated_by"] = MODEL
    return data


# Layer 2: investigation agent

INVESTIGATE_PROMPT = """You are a SOC analyst investigating one finding.

You have tools that read this log file. Decide what to look at based on what you
find; do not follow a fixed script.

Rules:
- Use at least one tool before concluding. Never assume what the logs contain.
- Choose follow-up queries based on what the previous result showed.
- Base every statement on data you actually retrieved.
- Say so plainly if the evidence is insufficient.
- Be brief: an analyst is reading this between other alerts.

Useful lines of enquiry, depending on the finding:
- Is the destination domain used by other hosts, or only this one?
- Is this volume or timing unusual for this host specifically?
- Was the activity outside working hours?
- Did the host contact anything else unusual around the same time?

Write the final answer as a SOC handoff note, not prose. Exact format:

ASSESSMENT: benign | suspicious | malicious | inconclusive - one clause of why.
Hedge honestly ("likely", "possibly") when the evidence is not conclusive;
logs alone rarely prove intent.
EVIDENCE:
- one fact per line, telegraphic fragments, numbers first (counts, bytes, times)
- 3 to 6 lines
GAPS:
- what the logs could not establish (omit the section if nothing)
NEXT: the single most useful action, one line

Under 120 words total. No filler, no restating the finding, no hedging
sentences. Facts only."""


TYPE_MAP = {str: "string", int: "integer", float: "number", bool: "boolean"}


def _json_type(hint) -> dict:
    """Translate one Python type hint into a JSON Schema property."""
    origin = get_origin(hint)
    # `str | None` (types.UnionType) or Optional[str] (typing.Union): the None
    # half only marks the parameter as optional, so describe the real type.
    if origin in (Union, types.UnionType):
        args = [a for a in get_args(hint) if a is not type(None)]
        return _json_type(args[0])
    # Literal["ALLOWED", "BLOCKED"] becomes an enum of those exact values.
    if origin is Literal:
        return {"type": "string", "enum": list(get_args(hint))}
    return {"type": TYPE_MAP.get(hint, "string")}


def build_tool_schema(fn) -> dict:
    """Derive an OpenAI tool schema from a plain Python function.
    Name comes from fn.__name__, description from the docstring, parameter
    types from the type hints, and required list from which parameters
    lack a default value.
    """
    hints = get_type_hints(fn)
    properties = {}
    required = []
    for name, param in inspect.signature(fn).parameters.items():
        if param.default is inspect.Parameter.empty:
            required.append(name)
        properties[name] = _json_type(hints.get(name, str))
    return {"type": "function", "function": {"name": fn.__name__, "description": inspect.getdoc(fn), "parameters": {"type": "object", "properties": properties, "required": required}}}


def investigate_finding(finding: dict, registry: dict, pseudo=None) -> dict:
    if not enabled():
        return {"assessment": "AI investigation unavailable (no API key configured).",
                "steps": 0, "generated_by": "fallback"}

    # Pseudonymization happens at the wire: everything sent is scrubbed,
    # everything received is unscrubbed. Tools and the loop see real values.
    scrub = pseudo.scrub if pseudo else (lambda t: t)
    unscrub = pseudo.unscrub if pseudo else (lambda t: t)

    messages = [
        {"role": "system", "content": INVESTIGATE_PROMPT},
        {"role": "user", "content": scrub(json.dumps({
            "finding": {k: finding[k] for k in
                        ("detector", "entity", "reason", "confidence", "mitre",
                         "first_seen", "last_seen") if k in finding},
            "suggested_filter": finding.get("filter", {}),
        }))},
    ]
    
    tools = [build_tool_schema(fn) for fn in registry.values()]

    #AGENT LOOP:
    steps = 0
    tokens = 0
    # Every tool call is recorded for the UI's "show the agent's work" panel:
    # real values (the analyst's view), not the aliases sent to the model.
    trace = []
    for _ in range(MAX_AGENT_STEPS):
        response = _client.chat.completions.create(
            model=MODEL, messages=messages, tools=tools
        )
        tokens += response.usage.total_tokens
        message = response.choices[0].message
        if not message.tool_calls:
            return {"assessment": unscrub(message.content), "steps": steps,
                    "tokens": tokens, "trace": trace, "generated_by": MODEL}
        messages.append(message)
        for call in message.tool_calls:
            args = json.loads(unscrub(call.function.arguments))
            fn = registry.get(call.function.name)
            try:
                result = fn(**args) if fn else {"error": "unknown tool"}
            except Exception as exc:
                result = {"error": str(exc)}
            trace.append({"tool": call.function.name, "arguments": args,
                          "result": result})
            messages.append({"role": "tool", "tool_call_id": call.id,
                             "content": scrub(json.dumps(result, default=str))})
        steps += 1
    #Last call with tools disabled so model conclude with gathered information:
    response = _client.chat.completions.create(
        model=MODEL, messages=messages, tools=tools, tool_choice="none"
    )
    tokens += response.usage.total_tokens
    return {"assessment": unscrub(response.choices[0].message.content),
            "steps": steps, "tokens": tokens, "trace": trace, "generated_by": MODEL}
