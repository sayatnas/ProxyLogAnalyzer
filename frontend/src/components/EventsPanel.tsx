import { useEffect, useState } from "react";
import { authedFetch } from "../api";
import type { LogEvent } from "../types";

interface Props {
  uploadId: string;
  filter: Record<string, string | number>;
  entityFilter: Record<string, string | number>;
}

export default function EventsPanel({ uploadId, filter, entityFilter }: Props) {
  const [mode, setMode] = useState<"finding" | "entity">("finding");
  const [events, setEvents] = useState<LogEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const active = mode === "finding" ? filter : entityFilter;
    const qs = new URLSearchParams(Object.entries(active).map(([k, v]) => [k, String(v)])).toString();
    setLoading(true);
    setError(null);
    authedFetch(`/api/results/${uploadId}/events?${qs}`)
      .then(async (response) => {
        if(!response.ok) { throw new Error(`Requested failed (${response.status})`); }
        return response.json();
      })
      .then(data => {setEvents(data.events);
        setTotal(data.total_matched);})
      .catch(err => setError(String(err)))
      .finally(() => setLoading(false));
  }, [uploadId, mode]);

  return (
    <div className="events">
      <div className="events-toolbar">
        <button
          className={mode === "finding" ? "tab active" : "tab"}
          onClick={() => setMode("finding")}
        >
          Evidence
        </button>
        <button
          className={mode === "entity" ? "tab active" : "tab"}
          onClick={() => setMode("entity")}
        >
          All activity
        </button>
        {!loading && <span className="muted">{total} matching events</span>}
      </div>

      {loading && <p className="muted">Loading events&hellip;</p>}
      {error && <p className="status error">{error}</p>}

      {!loading && !error && events.length > 0 && (
        <table className="events-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>User</th>
              <th>Source IP</th>
              <th>Domain</th>
              <th>Action</th>
              <th>Sent</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e, i) => (
              <tr key={i} className={e.action === "BLOCKED" ? "blocked" : undefined}>
                <td>{e.timestamp.slice(11, 19)}</td>
                <td>{e.user}</td>
                <td>{e.src_ip}</td>
                <td>{e.domain}</td>
                <td>{e.action}</td>
                <td>{e.bytes_sent.toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {!loading && !error && events.length === 0 && (
        <p className="muted">No matching events.</p>
      )}
    </div>
  );
}
