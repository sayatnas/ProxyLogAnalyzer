import type { ReactNode } from "react";

// IPs first in the alternation so 10.0.1.16 is not half-matched as a domain.
// A domain's last label must be alphabetic, which keeps decimals like "192.8"
// from matching. String.split keeps the captured matches in the result at odd
// indices, so classification is by position, no re-testing needed.
const ENTITY =
  /(\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.[a-z]{2,}\b)/gi;

const IP = /^(?:\d{1,3}\.){3}\d{1,3}$/;

/** Wrap IPs and domains in colored chips. Backticks from the model are
 *  stripped; the chip is the emphasis. */
export function highlight(text: string): ReactNode[] {
  return text
    .replace(/`/g, "")
    .split(ENTITY)
    .map((part, i) => {
      if (i % 2 === 0) return part;
      const cls = IP.test(part) ? "ent ent-ip" : "ent ent-domain";
      return (
        <span key={i} className={cls}>
          {part}
        </span>
      );
    });
}
