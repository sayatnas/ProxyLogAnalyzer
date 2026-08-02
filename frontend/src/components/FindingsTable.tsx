import { Fragment, useState } from "react";
import type { Finding, Investigation } from "../types";
import EventsPanel from "./EventsPanel";
import InvestigatePanel from "./InvestigatePanel";

interface Props {
  findings: Finding[];
  uploadId: string;
  detectors: string[];
}

function severityOf(confidence: number): string {
  if (confidence >= 0.8) {
    return "high";
  } else if (confidence >= 0.5) {
    return "medium";
  } else {
    return "low";
  }
}

export default function FindingsTable({ findings, uploadId, detectors }: Props) {
  const [openRow, setOpenRow] = useState<string | null>(null);
  // Investigations cached here so collapsing a row does not discard them.
  const [investigations, setInvestigations] = useState<Record<string, Investigation>>({});
  const detectorList = detectors.join(", ");
  if (findings.length === 0) {
    return (
      <section>
        <h2>Findings</h2>
        <p className="muted">
          No anomalies detected. Checked by {detectors.length} detectors: {detectorList}.
        </p>
      </section>
    );
  }

  return (
    <section>
      <h2>Findings ({findings.length}) <span className="muted" style={{fontSize: "0.8rem", fontWeight: "normal"}}>from {detectors.length} detectors ({detectorList}); click a row to see the supporting log lines</span></h2>
      <table className="findings">
        <thead>
          <tr>
            <th></th>
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
            const key = finding.detector + finding.entity;
            return (
              <Fragment key={key}>
              <tr className={`sev-${sev} clickable`}
                  onClick={() => setOpenRow(openRow === key ? null : key)}>
                  <td className="chev-cell">
                    <span className={openRow === key ? "chev open" : "chev"} >&#9654;</span>
                  </td>
                  <td><span className={`badge sev-${sev}`}>{sev}</span></td>
                  <td>{finding.detector}</td>
                  <td>{finding.entity}</td>
                  <td>{finding.mitre || "-"}</td>
                  <td>{(finding.confidence * 100).toFixed(0) + "%"}</td>
                  <td>{finding.reason}</td>
              </tr>
              {openRow === key && (
                <tr>
                  <td colSpan={7}>
                    <InvestigatePanel
                      uploadId={uploadId}
                      finding={finding}
                      cachedResult={investigations[key] ?? null}
                      onResult={(r) =>
                        setInvestigations((prev) => ({ ...prev, [key]: r }))
                      }
                    />
                    <EventsPanel
                      uploadId={uploadId}
                      filter={finding.filter}
                      entityFilter={finding.entity_filter}
                    />
                  </td>
                </tr>
              )}
            </Fragment>
            );
          })}
        </tbody>
      </table>
    </section>
  );
}
