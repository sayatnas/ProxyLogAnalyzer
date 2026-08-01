import type { TimelineEvent } from "../types";

interface Props {
  events: TimelineEvent[];
}

export default function Timeline({ events }: Props) {
  if (events.length === 0) {
    return (
      <section>
        <h2>Timeline</h2>
        <p className="muted">No anomalous events detected.</p>
      </section>
    );
  }

  return (
    <section>
      <h2>Timeline</h2>
      <ol className="timeline">
        {events.map((e) => (
          <li key={`${e.time}-${e.entity}`} className={`tl-event sev-${e.severity}`}>
            <span className="tl-time">{e.time.slice(11, 16)}</span>
            <span className={`badge sev-${e.severity}`}>{e.severity}</span>
            <span className="tl-desc">
              <strong>{e.entity}</strong>: {e.description}
            </span>
          </li>
        ))}
      </ol>
    </section>
  );
}
