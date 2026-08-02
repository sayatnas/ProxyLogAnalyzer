import { useState } from "react";
import { authedFetch } from "../api";
import { highlight } from "../highlight";
import type { Summary } from "../types";

interface Props {
  uploadId: string;
}

// Map the model's four assessments onto the severity colors the table uses.
const badgeClass: Record<Summary["assessment"], string> = {
  malicious: "sev-high",
  suspicious: "sev-medium",
  benign: "sev-low",
  inconclusive: "",
};

export default function SummaryPanel({ uploadId }: Props) {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSummarize = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await authedFetch(`/api/results/${uploadId}/summarize`, {
        method: "POST",
      });
      if (!response.ok) {
        throw new Error(`Request failed (${response.status})`);
      }
      setSummary(await response.json());
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  if (!summary) {
    return (
      <div className="investigate">
        {!loading && (
          <button className="investigate-btn" onClick={handleSummarize}>
            AI Summarize
          </button>
        )}
        {!loading && (
          <span className="muted">
            Generates a triage summary of the findings below.
          </span>
        )}
        {loading && <p className="muted">Summarizing&hellip;</p>}
        {error && <p className="status error">{error}</p>}
      </div>
    );
  }

  const fallback = summary.generated_by === "fallback";
  return (
    <section className="summary">
      <h2>
        AI triage summary{" "}
        <span className={`badge ai-badge ${badgeClass[summary.assessment]}`}>
          AI assessment: {summary.assessment}
        </span>
      </h2>
      {summary.summary.includes("\n") ? (
        <ol className="ranking">
          {summary.summary
            .split("\n")
            .filter((line) => line.trim())
            .map((line, i) => (
              <li key={i}>{highlight(line)}</li>
            ))}
        </ol>
      ) : (
        <p>{highlight(summary.summary)}</p>
      )}

      {summary.correlations.length > 0 && (
        <>
          <h3>Correlated entities</h3>
          <ul>
            {summary.correlations.map((c, i) => (
              <li key={i}>{highlight(c)}</li>
            ))}
          </ul>
        </>
      )}

      {summary.recommended_actions.length > 0 && (
        <>
          <h3>Recommended actions</h3>
          <ul>
            {summary.recommended_actions.map((a, i) => (
              <li key={i}>{highlight(a)}</li>
            ))}
          </ul>
        </>
      )}

      {summary.leads && summary.leads.length > 0 && (
        <div className="leads">
          <h3>
            Leads{" "}
            <span className="muted">AI sweep, unverified: pivot before acting</span>
          </h3>
          {summary.leads.map((lead, i) => (
            <div key={i} className="lead">
              <p>
                {highlight(lead.entity)}
                {lead.confidence !== undefined && (
                  <span className="muted"> · {Math.round(lead.confidence * 100)}%</span>
                )}
              </p>
              {lead.observation && <p>{highlight(lead.observation)}</p>}
              <p className="lead-why">{highlight(lead.why_suspicious)}</p>
            </div>
          ))}
        </div>
      )}

      <p className="muted generated-by">
        {fallback
          ? "AI summary unavailable; showing a template summary."
          : `${summary.generated_by}` +
            (summary.steps !== undefined ? ` · ${summary.steps} ${summary.steps === 1 ? "round" : "rounds"} of tool calls` : "") +
            (summary.tokens ? ` · ${summary.tokens.toLocaleString()} tokens` : "") +
            ". AI ranks and verifies the statistical findings; it does not decide what is anomalous."}
      </p>

      {summary.trace && summary.trace.length > 0 && (
        <details className="trace">
          <summary>
            Show the triage's work ({summary.trace.length}{" "}
            {summary.trace.length === 1 ? "tool call" : "tool calls"})
          </summary>
          {summary.trace.map((step, i) => (
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
    </section>
  );
}
