import { useEffect, useState } from "react";
import { authedFetch } from "../api";
import type { LogEvent } from "../types";

// Histogram of gaps between consecutive events. Beaconing shows as a single
// tight spike (a robotic timer); human browsing scatters. Drawn from the
// events already fetched, so it costs nothing extra.
function IntervalHistogram({ events }: { events: LogEvent[] }) {
  if (events.length < 8) return null;
  const times = events
    .map((e) => new Date(e.timestamp).getTime())
    .sort((a, b) => a - b);
  const gaps = times.slice(1).map((t, i) => (t - times[i]) / 1000);
  const sorted = [...gaps].sort((a, b) => a - b);
  const p95 = sorted[Math.floor(sorted.length * 0.95)] || 1;
  const median = sorted[Math.floor(sorted.length / 2)];
  const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
  const variance = gaps.reduce((a, b) => a + (b - mean) ** 2, 0) / gaps.length;
  const cv = mean > 0 ? Math.round((Math.sqrt(variance) / mean) * 100) : 0;
  const bins = new Array(24).fill(0);
  for (const g of gaps) {
    bins[Math.min(Math.floor((g / p95) * 23), 23)] += 1;
  }
  const max = Math.max(...bins, 1);
  return (
    <div className="chart intervals">
      <h4>
        Seconds between requests{" "}
        <span className="muted">
          median {Math.round(median)}s, variation {cv}%
          {cv < 15 ? ", highly regular: timer-like" : ""}
        </span>
      </h4>
      <svg viewBox="0 0 240 50" preserveAspectRatio="none">
        {bins.map((b, i) =>
          b > 0 ? (
            <rect key={i} x={i * 10} y={50 - (b / max) * 50}
                  width={9} height={(b / max) * 50} fill="#5b7fb3" />
          ) : null
        )}
      </svg>
      <div className="axis-x intervals-axis">
        <span>0s</span>
        <span>{Math.round(p95)}s</span>
      </div>
    </div>
  );
}

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
        if(!response.ok) { throw new Error(`Request failed (${response.status})`); }
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

      {!loading && !error && <IntervalHistogram events={events} />}

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
