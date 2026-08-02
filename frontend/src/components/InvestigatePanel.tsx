import { useState } from "react";
import { authedFetch } from "../api";
import { highlight } from "../highlight";
import type { Finding, Investigation } from "../types";

interface Props {
  uploadId: string;
  finding: Finding;
}

interface ParsedNote {
  assessment: string | null;
  evidence: string[];
  gaps: string[];
  next: string | null;
}

// The model is asked for ASSESSMENT / EVIDENCE / GAPS / NEXT. Parse it into
// sections; if the model went off-script, return null and the caller falls
// back to rendering the raw text.
function parseNote(text: string): ParsedNote | null {
  const note: ParsedNote = { assessment: null, evidence: [], gaps: [], next: null };
  let section: "evidence" | "gaps" | null = null;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    const upper = line.toUpperCase();
    if (upper.startsWith("ASSESSMENT:") || upper.startsWith("VERDICT:")) {
      note.assessment = line.slice(line.indexOf(":") + 1).trim();
      section = null;
    } else if (upper.startsWith("EVIDENCE")) {
      section = "evidence";
    } else if (upper.startsWith("GAPS")) {
      section = "gaps";
    } else if (upper.startsWith("NEXT:")) {
      note.next = line.slice(line.indexOf(":") + 1).trim();
      section = null;
    } else if (line.startsWith("-")) {
      (section === "gaps" ? note.gaps : note.evidence).push(line.replace(/^-\s*/, ""));
    }
  }
  return note.assessment || note.evidence.length > 0 ? note : null;
}

function assessmentClass(assessment: string): string {
  const a = assessment.toLowerCase();
  if (a.includes("malicious")) return "sev-high";
  if (a.includes("suspicious")) return "sev-medium";
  if (a.includes("benign")) return "sev-low";
  return "";
}

export default function InvestigatePanel({ uploadId, finding }: Props) {
  const [result, setResult] = useState<Investigation | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleInvestigate = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await authedFetch(`/api/results/${uploadId}/investigate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding_key: finding.detector + finding.entity }),
      });
      if (!response.ok) {
        throw new Error(`Request failed (${response.status})`);
      }
      setResult(await response.json());
    }
    catch (err) {
      setError(String(err));
      console.error(err);
    }
    finally {
      setLoading(false);
    }
  };

  return (
    <div className="investigate">
      {!result && !loading && (
        <button className="investigate-btn" onClick={handleInvestigate}>
          AI Investigate
        </button>
      )}
      {!result && !loading && (
        <span className="muted">
          An agent queries this log to build context around the finding. Takes
          10 to 30 seconds.
        </span>
      )}

      {loading && (
        <p className="muted">
          Investigating&hellip; the agent is querying the log.
        </p>
      )}
      {error && <p className="status error">{error}</p>}

      {result && (
        <div className="investigate-result">
          <h3 className="ai-title">AI investigation</h3>
          {(() => {
            const note = parseNote(result.assessment);
            if (!note) {
              return <div className="assessment">{highlight(result.assessment)}</div>;
            }
            return (
              <div className="investigate-note">
                {note.assessment && (
                  <p className="inv-assessment">
                    <span className={`badge ${assessmentClass(note.assessment)}`}>
                      {note.assessment.split(" - ")[0]}
                    </span>{" "}
                    {highlight(note.assessment.split(" - ").slice(1).join(" - "))}
                  </p>
                )}
                {note.evidence.length > 0 && (
                  <>
                    <h4>Evidence</h4>
                    <ul>
                      {note.evidence.map((e, i) => (
                        <li key={i}>{highlight(e)}</li>
                      ))}
                    </ul>
                  </>
                )}
                {note.gaps.length > 0 && (
                  <>
                    <h4>Gaps</h4>
                    <ul className="muted">
                      {note.gaps.map((gap, i) => (
                        <li key={i}>{highlight(gap)}</li>
                      ))}
                    </ul>
                  </>
                )}
                {note.next && (
                  <p className="inv-next">
                    <strong>Next:</strong> {highlight(note.next)}
                  </p>
                )}
              </div>
            );
          })()}
          <p className="muted generated-by">
            {result.generated_by} · {result.steps}{" "}
            {result.steps === 1 ? "round" : "rounds"} of tool calls
            {result.tokens ? ` · ${result.tokens.toLocaleString()} tokens` : ""}
          </p>

          {result.trace && result.trace.length > 0 && (
            <details className="trace">
              <summary>
                Show the agent's work ({result.trace.length}{" "}
                {result.trace.length === 1 ? "tool call" : "tool calls"})
              </summary>
              {result.trace.map((step, i) => (
                <div key={i} className="trace-step">
                  <code>
                    {step.tool}(
                    {Object.entries(step.arguments)
                      .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
                      .join(", ")}
                    )
                  </code>
                  <pre>{JSON.stringify(step.result, null, 2)}</pre>
                </div>
              ))}
            </details>
          )}
        </div>
      )}
    </div>
  );
}
