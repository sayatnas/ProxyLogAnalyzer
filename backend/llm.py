"""AI layer.

  triage_findings()     tool-augmented triage of all findings, on demand
  investigate_finding() bounded tool loop over one finding, on demand

Both are bounded agent loops over the same read-only tool registry; the
statistics decide what is anomalous, the model verifies, ranks, and explains.
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


# Layer 1: triage

TRIAGE_PROMPT = """You are triaging one proxy log file for a SOC analyst.
You are given pre-computed statistical findings, and tools that read the log.

Work in two phases.

Phase 1, VERIFY AND RANK: profile each flagged entity and its main
destination domains with the tools. A finding's severity depends on context
the statistics cannot see (a spike to a malware-category domain outranks a
bigger spike to a CDN). Do not rank on the finding text alone. Then check
whether findings share entities, domains, or time windows.

Phase 2, SWEEP: call get_overview and look for suspicious activity NOT
covered by any finding: domains contacted by few hosts, names imitating
brands or services (typosquats), odd category mixes, quiet traffic to
uncategorized destinations. The detectors only catch statistical outliers;
your job here is what needs judgement. Verify anything promising with the
other tools before reporting it. Report these as leads, never as findings.

Rules:
- Base every statement on the findings or on tool results. Never invent
  entities or numbers.
- Do not speculate about attacker identity or attribution.
- If the evidence does not support a judgement, use "inconclusive".
- Telegraphic fragments, entity and numbers first, no filler words.
- The analyst already sees the stats block, the findings table, and a
  timeline of the findings. Do not restate them. Your value is judgement:
  which finding matters most and why, what the tools revealed that the
  detectors could not see, how findings relate, and what to do.

When done investigating, return ONLY JSON matching:
{
  "assessment": "benign" | "suspicious" | "malicious" | "inconclusive",
  "summary": "a single string, one line per finding separated by \\n (not an array), worst first; each line: entity, then why it ranks there, citing the tool evidence that decided it; under 25 words per line",
  "correlations": ["ONLY links you verified: an entity in multiple findings, a shared domain, an overlapping time window; each entry ONE sentence naming both sides; at most 3, each a DIFFERENT link; never report the absence of a link; empty list if none"],
  "recommended_actions": ["imperative fragments, most urgent first"],
  "leads": [{"entity": "domain or IP", "observation": "what you saw, with numbers", "why_suspicious": "the judgement, one fragment", "confidence": 0.55, "filter": {"domain": "..."}}]
}
Leads are hypotheses for a human to verify, not detections: include only what
you checked with tools, give honest sub-certain confidence values, and use
an empty list when the sweep found nothing. Rarity alone is weak evidence,
especially in a small log where most domains are single-host; a lead needs a
second signal on top (a deceptive name, a bad category, odd timing). If there
are no findings, say so in the first summary line rather than ranking normal
activity. Never report an entity or domain
that already appears in a finding as a lead; leads exist only for what the
findings do not cover. The filter object may use keys src_ip, domain, user,
time_from, time_to."""

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
            "correlations": [],
            "recommended_actions": [],
            "leads": [],
            "generated_by": "fallback",
        }
    high = [f for f in findings if f["confidence"] >= 0.8]
    return {
        "assessment": "suspicious" if high else "inconclusive",
        "summary": (f"{len(findings)} anomalies detected, {len(high)} at high confidence. "
                    "AI summary unavailable; findings below are unaffected."),
        "correlations": [],
        "recommended_actions": ["Review each finding and pivot into its supporting events."],
        "leads": [],
        "generated_by": "fallback",
    }


def triage_findings(stats: dict, findings: list[dict], registry: dict,
                    pseudo=None) -> dict:
    """Tool-augmented triage of a whole log's findings.

    Same output contract as the old narration-only summary, but the model may
    use the read-only tools to verify context (domain categories, host
    behaviour) before ranking, so severity reflects what the statistics
    cannot see.
    """
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
    messages = [
        {"role": "system", "content": TRIAGE_PROMPT},
        {"role": "user", "content": scrub(json.dumps(payload))},
    ]
    tools = [build_tool_schema(fn) for fn in registry.values()]

    steps = 0
    tokens = 0
    trace = []

    def unscrub_values(obj):
        """Unscrub every string in a parsed structure. Running the regex on
        raw JSON text misses aliases that sit right after an escape sequence
        (in `...\\nhost-1` the escape's `n` touches `host`, so there is no
        word boundary); parsed strings have real newlines and no escapes."""
        if isinstance(obj, str):
            return unscrub(obj)
        if isinstance(obj, list):
            return [unscrub_values(v) for v in obj]
        if isinstance(obj, dict):
            return {k: unscrub_values(v) for k, v in obj.items()}
        return obj

    def finish(content) -> dict:
        """Parse and validate the model's final JSON; fall back if bad."""
        try:
            data = unscrub_values(json.loads(content))
        except (TypeError, json.JSONDecodeError) as exc:
            log.warning("triage returned invalid JSON: %s", exc)
            return _fallback_summary(findings)
        # The model sometimes expresses "lines" as a JSON array; the UI
        # contract is a string, so normalise before validating.
        if isinstance(data.get("summary"), list):
            data["summary"] = "\n".join(str(s) for s in data["summary"])
        if data.get("assessment") not in ASSESSMENTS or not data.get("summary"):
            log.warning("triage failed validation: %s", data)
            return _fallback_summary(findings)
        # With no findings the model tends to rank normal activity as if it
        # were findings; stamp the true provenance rather than trusting the
        # prompt to.
        if not findings:
            data["summary"] = ("No detector findings; AI sweep observations only.\n"
                               + data["summary"])
        # A lead the UI can render needs entity and why_suspicious; drop
        # anything malformed rather than trusting the prompt was followed.
        # Leads must also not duplicate a finding: the sweep exists for what
        # the detectors did NOT flag. Exact match against the findings'
        # atomic identifiers, not substring: a lead that merely mentions a
        # flagged host alongside a new domain must survive, because hiding a
        # real lead is worse than showing a duplicate.
        flagged = set()
        for f in findings:
            flagged.update(f.get("entity", "").replace("->", " ").split())
        leads = data.get("leads")
        cleaned = []
        if isinstance(leads, list):
            for lead in leads:
                if not (isinstance(lead, dict)
                        and isinstance(lead.get("entity"), str) and lead["entity"]
                        and isinstance(lead.get("why_suspicious"), str)
                        and lead["why_suspicious"]):
                    continue
                if lead["entity"].strip() in flagged:
                    continue
                cleaned.append(lead)
        # Strongest first, so if the cap ever truncates it drops the weakest
        # leads, not whichever the model happened to list last. The floor
        # exists because rarity collapses as a signal on small logs (every
        # domain is single-host) and the model reports the noise at honestly
        # low confidence; observed junk sits at 0.3-0.47, real leads at 0.56+.
        cleaned = [l for l in cleaned if (l.get("confidence") or 0) >= 0.5]
        cleaned.sort(key=lambda l: l.get("confidence") or 0, reverse=True)
        data["leads"] = cleaned[:5]
        correlations = data.get("correlations")
        data["correlations"] = correlations[:3] if isinstance(correlations, list) else []
        data.update({"generated_by": MODEL, "steps": steps,
                     "tokens": tokens, "trace": trace})
        return data

    try:
        for _ in range(MAX_AGENT_STEPS):
            response = _client.chat.completions.create(
                model=MODEL, messages=messages, tools=tools,
                response_format={"type": "json_object"},
            )
            tokens += response.usage.total_tokens
            message = response.choices[0].message
            if not message.tool_calls:
                return finish(message.content)
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
        response = _client.chat.completions.create(
            model=MODEL, messages=messages, tools=tools, tool_choice="none",
            response_format={"type": "json_object"},
        )
        tokens += response.usage.total_tokens
        return finish(response.choices[0].message.content)
    except Exception as exc:
        log.warning("triage loop failed: %s", exc)
        return _fallback_summary(findings)


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
