"""Pseudonymization for the AI layer.

The model reasons over aliases (user-3, host-7)
Usernames and internal IPs never reach the API.
Domains stay visible for evidence.
"""
import re


class Pseudonymizer:
    def __init__(self, records: list[dict]):
        self.forward: dict[str, str] = {}
        self.reverse: dict[str, str] = {}
        users = sorted({r["user"] for r in records if r["user"]})
        ips = sorted({r["src_ip"] for r in records if r["src_ip"]})
        for i, u in enumerate(users, 1):
            self.forward[u] = f"user-{i}"
            self.reverse[f"user-{i}"] = u
        for i, ip in enumerate(ips, 1):
            self.forward[ip] = f"host-{i}"
            self.reverse[f"host-{i}"] = ip
        self._scrub_re = _compile(self.forward)
        self._unscrub_re = _compile(self.reverse, ignorecase=True)

    def scrub(self, text: str) -> str:
        """Replace every real name in the text with its alias."""
        return self._scrub_re.sub(lambda m: self.forward[m.group()], text)

    def unscrub(self, text: str) -> str:
        """Replace every alias in the text with the real name."""
        return self._unscrub_re.sub(lambda m: self.reverse[m.group().lower()], text)


def _compile(mapping: dict[str, str], ignorecase: bool = False) -> re.Pattern:
    """One alternation regex matching any key as a whole word.
    Longest-first ordering keeps overlapping aliases (user-3 vs user-33) unambiguous.
    """
    if not mapping:
        return re.compile(r"(?!)")  # matches nothing
    keys = sorted(mapping, key=len, reverse=True)
    return re.compile(r"\b(?:" + "|".join(re.escape(k) for k in keys) + r")\b",
                      re.IGNORECASE if ignorecase else 0)
