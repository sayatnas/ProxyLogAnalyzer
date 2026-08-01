import type { Finding } from "../types";

interface Props {
  findings: Finding[];
}

// TODO(you): map confidence to the same buckets the backend uses for the
// timeline ("high" >= 0.8, "medium" >= 0.5, else "low"). Returns the css
// suffix used below: "high" | "medium" | "low".
function severityOf(confidence: number): string {
  if (confidence >= 0.8) {
    return "high";
  } else if (confidence >= 0.5) {
    return "medium";
  } else {
    return "low";
  }
}

export default function FindingsTable({ findings }: Props) {
  if (findings.length === 0) {
    return (
      <section>
        <h2>Findings</h2>
        <p className="muted">No anomalies detected.</p>
      </section>
    );
  }

  return (
    <section>
      <h2>Findings ({findings.length})</h2>
      <table className="findings">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Detector</th>
            <th>Entity</th>
            <th>MITRE</th>
            <th>Confidence</th>
            <th>Reason</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding) => {
            const sev = severityOf(finding.confidence);
            return (
              <tr key={finding.detector + finding.entity} className={`sev-${sev}`}>
                <td><span className={`badge sev-${sev}`}>{sev}</span></td>
                <td>{finding.detector}</td>
                <td>{finding.entity}</td>
                <td>{finding.mitre || "-"}</td>
                <td>{(finding.confidence * 100).toFixed(0) + "%"}</td>
                <td>{finding.reason}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </section>
  );
}
