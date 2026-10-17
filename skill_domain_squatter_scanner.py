"""skill-domain-squatter-scanner: find squat-able domains hiding in agent skills.

On 2026-10-17, AIR Security Research Lab found the hallucinated domain
``render-internal.com`` — unregistered, production tokens pointed at it —
inside OpenAI's OFFICIAL skills repo (skill told Render apps to send
production tokens to it). Researchers registered it themselves before
attackers did. If the vendor's own skill ships a squat-able domain,
every skill everywhere needs this scan.

What this does: scans installed agent skills (Claude Code
``~/.claude/skills``, OpenAI skills dirs, MCP skill bundles) for every
domain/URL in instructions and checks, deterministically, whether each
domain is REGISTERED (resolves) or UNREGISTERED (does not resolve) —
plus lookalike checking against domains you actually own.

Deterministic, not a classifier: a DNS check, not an accuracy play.

What this does NOT detect: typo-squats of domains you did not list in
``--known`` (we cannot read your mind); domains that resolve today but
expire tomorrow (re-run on a schedule); malicious content — pair with
an agent-skills content scanner.
"""

import argparse
import json
import os
import re
import socket
import sys
from urllib.parse import urlparse

# Domains/URLs in markdown links, bare URLs, quotes, and config strings.
URL_RE = re.compile(
    r"""(?xi)
    (?:https?://|wss?://)      # scheme
    ([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)
    | \b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,})\b
    """)

SKIP_SUFFIXES = (".md", ".txt", ".json", ".yaml", ".yml", ".toml",
                 ".py", ".js", ".ts", ".sh", "")

DEFAULT_SKILL_DIRS = (
    os.path.expanduser("~/.claude/skills"),
    os.path.expanduser("~/.codex/skills"),
    os.path.expanduser("~/.config/mcp/skills"),
)


def extract_domains(text):
    """Return the sorted set of domains found in text (lowercased)."""
    found = set()
    for m in URL_RE.finditer(text or ""):
        dom = (m.group(1) or m.group(2) or "").lower().rstrip(".")
        if not dom or ".." in dom:
            continue
        # Bare-word matches need at least one dot and a sane TLD length.
        found.add(dom)
    return sorted(found)


def _resolve(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except OSError:
        return False


def levenshtein(a, b):
    a, b = (a or "").lower(), (b or "").lower()
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def classify(domain, resolve_fn=None, known_domains=()):
    """Classify one domain.

    Returns {"domain", "status", "detail"} where status is one of:
    REGISTERED, UNREGISTERED, DNS-ERROR, LOOKALIKE.
    resolve_fn(domain) -> True/False/None (None = DNS error).
    """
    resolve = resolve_fn or _resolve
    known = {k.lower() for k in (known_domains or ())}
    if domain.lower() in known:
        return {"domain": domain, "status": "REGISTERED",
                "detail": "listed in --known (yours)"}
    for k in known:
        if 0 < levenshtein(domain, k) <= 2:
            return {"domain": domain, "status": "LOOKALIKE",
                    "detail": "within edit distance 2 of your domain %r "
                              "— defensively register it" % k}
    try:
        alive = resolve(domain)
    except Exception:
        alive = None
    if alive is None:
        return {"domain": domain, "status": "DNS-ERROR",
                "detail": "DNS lookup errored — retry, do not trust"}
    if alive:
        return {"domain": domain, "status": "REGISTERED",
                "detail": "resolves today — re-check on expiry schedule"}
    return {"domain": domain, "status": "UNREGISTERED",
            "detail": "does not resolve — SQUAT-ABLE: register defensively "
                      "or remove from the skill"}


def scan_skills(skills_dirs, resolve_fn=None, known_domains=()):
    """Scan skill files; return {"skills", "domains", "findings"}.

    findings: list of classify() dicts with an added "skills" list of
    the skill files that mention the domain.
    """
    resolve = resolve_fn or _resolve
    domain_sources = {}
    skill_files = []
    for d in skills_dirs:
        if not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            for fn in files:
                if not fn.lower().endswith(SKIP_SUFFIXES):
                    continue
                path = os.path.join(root, fn)
                try:
                    with open(path, "r", encoding="utf-8",
                              errors="replace") as fh:
                        text = fh.read(200_000)
                except OSError:
                    continue
                skill_files.append(path)
                for dom in extract_domains(text):
                    domain_sources.setdefault(dom, set()).add(path)
    findings = []
    for dom in sorted(domain_sources):
        c = classify(dom, resolve_fn=resolve,
                     known_domains=known_domains)
        c["skills"] = sorted(domain_sources[dom])
        findings.append(c)
    return {"skills": sorted(skill_files),
            "domains": sorted(domain_sources),
            "findings": findings}


def render_markdown(report):
    unreg = [f for f in report["findings"]
             if f["status"] in ("UNREGISTERED", "LOOKALIKE", "DNS-ERROR")]
    lines = ["# Skill Domain Squat Report", "",
             "- Skill files scanned: %d" % len(report["skills"]),
             "- Unique domains found: %d" % len(report["domains"]),
             "- Flags raised: %d" % len(unreg), ""]
    if unreg:
        lines.append("## Flags — act on these")
        for f in unreg:
            lines.append("- **%s** `%s` — %s" %
                         (f["status"], f["domain"], f["detail"]))
            for s in f["skills"]:
                lines.append("  - in `%s`" % s)
        lines.append("")
    lines.append("## All domains")
    for f in report["findings"]:
        lines.append("- `%s` — %s" % (f["domain"], f["status"]))
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Scan agent skills for unregistered / lookalike domains.")
    ap.add_argument("--skills-dir", action="append", default=[],
                    help="skill directory to scan (repeatable)")
    ap.add_argument("--known", action="append", default=[],
                    help="domain you own/control (repeatable)")
    ap.add_argument("--json", dest="as_json", action="store_true")
    ap.add_argument("--out", default="-")
    args = ap.parse_args(argv)
    dirs = args.skills_dir or list(DEFAULT_SKILL_DIRS)
    report = scan_skills(dirs, known_domains=args.known)
    out = json.dumps(report, indent=2) if args.as_json \
        else render_markdown(report)
    if args.out == "-":
        sys.stdout.write(out)
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out)
    bad = [f for f in report["findings"]
           if f["status"] in ("UNREGISTERED", "LOOKALIKE")]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
