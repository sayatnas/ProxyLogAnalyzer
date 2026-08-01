import type { Stats } from "../types";

interface Props {
  stats: Stats;
}

export default function StatsBar({ stats }: Props) {
  const items: [string, string | number][] = [
    ["Records", stats.total_records],
    ["Skipped lines", stats.skipped_lines],
    ["Users", stats.unique_users],
    ["Domains", stats.unique_domains],
    ["Source IPs", stats.unique_ips],
    ["Blocked", stats.blocked_count],
  ];

  return (
    <section className="stats">
      {items.map(([label, value]) => (
        <div className="stat" key={label}>
          <div className="stat-value">{value}</div>
          <div className="stat-label">{label}</div>
        </div>
      ))}
      <div className="stat">
        <div className="stat-value">
          {stats.time_range.start.slice(11, 16)}&ndash;{stats.time_range.end.slice(11, 16)}
        </div>
        <div className="stat-label">Time range</div>
      </div>
    </section>
  );
}
