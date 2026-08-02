import type { Charts } from "../types";

interface Props {
  charts: Charts;
}

const W = 800;
const H = 120;

function mb(bytes: number): string {
  return (bytes / 1e6).toFixed(1) + " MB";
}

export default function ChartsPanel({ charts }: Props) {
  const { activity, bytes_by_host } = charts;
  const max = Math.max(...activity.counts, 1);
  const barW = W / activity.counts.length;
  const maxBytes = Math.max(...bytes_by_host.map((h) => h.bytes), 1);
  const midMs =
    (new Date(activity.start).getTime() + new Date(activity.end).getTime()) / 2;
  const mid = new Date(midMs).toTimeString().slice(0, 5);

  return (
    <section className="charts">
      <div className="chart">
        <h3>
          Requests over time{" "}
          <span className="muted">
            per {Math.round(activity.bucket_seconds / 60)} min
          </span>
        </h3>
        <div className="plot">
          <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none">
            {activity.counts.map((c, i) =>
              c > 0 ? (
                <rect
                  key={i}
                  x={i * barW}
                  y={H - (c / max) * H}
                  width={Math.max(barW - 0.5, 0.5)}
                  height={(c / max) * H}
                  fill="#5b7fb3"
                />
              ) : null
            )}
          </svg>
          <span className="y-max">{max}</span>
          <span className="y-zero">0</span>
        </div>
        <div className="axis-x">
          <span>{activity.start.slice(11, 16)}</span>
          <span>{mid}</span>
          <span>{activity.end.slice(11, 16)}</span>
        </div>
      </div>

      <div className="chart">
        <h3>
          Bytes sent by host <span className="muted">top {bytes_by_host.length}</span>
        </h3>
        {bytes_by_host.map((h) => (
          <div key={h.src_ip} className="hbar-row">
            <span className="hbar-label">{h.src_ip}</span>
            <div className="hbar-track">
              <div
                className="hbar"
                style={{ width: `${Math.max((h.bytes / maxBytes) * 100, 0.5)}%` }}
              />
            </div>
            <span className="hbar-value">{mb(h.bytes)}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
