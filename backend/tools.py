"""Agent tools: read-only functions investigation model can call.

build_registry creates tools per investigation,
safety: closed over one upload's parsed records
docstring doubles as tool description sent to model
llm.build_tool_schema derives schema from signature
parameters must be declared explicitly.
"""

from collections import Counter
from typing import Literal


def matches(record: dict, filters: dict) -> bool:
    """True when a parsed record satisfies every filter that was supplied.

    Filters are applied by this code against known field names; only the VALUES
    come from the request, so a caller cannot ask for arbitrary fields.
    """
    if (ip := filters.get("src_ip")) and record["src_ip"] != ip:
        return False
    if (domain := filters.get("domain")) and record["domain"] != domain:
        return False
    if (user := filters.get("user")) and record["user"] != user:
        return False
    if (action := filters.get("action")) and record["action"] != action:
        return False
    if (min_bytes := filters.get("min_bytes_sent")) and record["bytes_sent"] < int(min_bytes):
        return False
    if (start := filters.get("time_from")) and record["timestamp"] < start:
        return False
    if (end := filters.get("time_to")) and record["timestamp"] > end:
        return False
    return True


def build_registry(records: list[dict]) -> dict:
    """Build the tool registry for one upload. All tools are bounded and
    read-only."""

    def query_events(src_ip: str | None = None, domain: str | None = None,
                     user: str | None = None,
                     action: Literal["ALLOWED", "BLOCKED"] | None = None,
                     limit: int = 30):
        """Fetch raw proxy log lines from this upload. Filter by source IP,
        domain, user, or action (ALLOWED/BLOCKED). Use this to see the
        evidence behind the finding, or to see what else a host did."""
        filters = {k: v for k, v in
                   {"src_ip": src_ip, "domain": domain,
                    "user": user, "action": action}.items() if v}
        capped = min(int(limit), 50)
        matched = [r for r in records if matches(r, filters)]
        return {
            'total_matched': len(matched),
            'returned': min(len(matched), capped),
            'events': [
                {k: r[k] for k in ('timestamp', 'user', 'src_ip', 'domain',
                                   'action', 'bytes_sent', 'status')}
                for r in matched[:capped]
            ],
        }

    def get_domain_profile(domain: str):
        """How this domain is used across the WHOLE log: how many distinct
        hosts contacted it, how often, when it was first and last seen, and
        how much of its traffic was blocked. Use this to tell sanctioned
        software from attacker infrastructure: a domain many hosts use
        routinely is usually legitimate, while one contacted by a single
        host is not."""
        hits = [r for r in records if r['domain'] == domain]
        if not hits:
            return {'domain': domain, 'found': False}
        hosts = {r['src_ip'] for r in hits}
        blocked = sum(1 for r in hits if r['action'] == 'BLOCKED')
        return {
            'domain': domain,
            'found': True,
            'total_requests': len(hits),
            'distinct_hosts': len(hosts),
            'hosts': sorted(hosts)[:10],
            'category': hits[0]['category'],
            'first_seen': min(r['timestamp'] for r in hits),
            'last_seen': max(r['timestamp'] for r in hits),
            'blocked_ratio': round(blocked / len(hits), 3),
        }

    def get_entity_profile(src_ip: str):
        """A host's overall behaviour across the whole log: total requests,
        how many distinct domains it touched, its busiest domains, its
        blocked ratio, total bytes uploaded, and which hours it was active.
        Use this to judge whether the flagged activity is unusual FOR THIS
        HOST, and whether it was active outside working hours."""
        hits = [r for r in records if r['src_ip'] == src_ip]
        if not hits:
            return {'src_ip': src_ip, 'found': False}
        domains = Counter(r['domain'] for r in hits)
        blocked = sum(1 for r in hits if r['action'] == 'BLOCKED')
        return {
            'src_ip': src_ip,
            'found': True,
            'user': hits[0]['user'],
            'total_requests': len(hits),
            'distinct_domains': len(domains),
            'top_domains': domains.most_common(5),
            'blocked_ratio': round(blocked / len(hits), 3),
            'total_bytes_sent': sum(r['bytes_sent'] for r in hits),
            'active_hours': sorted({r['ts'].hour for r in hits}),
        }

    return {
        'query_events': query_events,
        'get_domain_profile': get_domain_profile,
        'get_entity_profile': get_entity_profile,
    }
