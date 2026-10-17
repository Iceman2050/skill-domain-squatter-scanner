# skill-domain-squatter-scanner

**The domain in your agent's skill is unregistered. Who registers it first — you, or the attacker?**

On 2026-10-17, AIR Security Research Lab found `render-internal.com` —
hallucinated, unregistered, with production tokens pointed at it —
inside **OpenAI's official skills repo**. The skill told Render apps to
send production tokens to it. Researchers registered the domain
themselves before attackers could (CSO). If the vendor's own skill
ships a squat-able domain, every skill everywhere needs this scan.

`skill-domain-squatter-scanner` audits installed agent skills (Claude
Code `~/.claude/skills`, OpenAI skills dirs, MCP skill bundles) for
every domain/URL in instructions, then checks — deterministically,
via DNS — whether each domain is REGISTERED or UNREGISTERED, and
flags lookalikes of domains you actually own (via `--known`).

This is a DNS check, not a classifier. Not a moving-target accuracy play.

## What it checks (per domain)

- **UNREGISTERED** — does not resolve. Squat-able: defensively register it or remove it from the skill.
- **LOOKALIKE** — within edit distance 2 of a `--known` domain you own. Register defensively.
- **REGISTERED** — resolves today (re-check on an expiry schedule).
- **DNS-ERROR** — lookup failed; retry, do not trust.

The CLI exits non-zero (`1`) when any UNREGISTERED or LOOKALIKE
domain is found, so it drops straight into CI or a cron.

## Install

Zero third-party dependencies — Python 3.9+ only.

```bash
git clone https://github.com/Iceman2050/skill-domain-squatter-scanner.git
cd skill-domain-squatter-scanner
pip install -e .
```

Or run the single file directly: `python3 skill_domain_squatter_scanner.py ...`

## Usage

```bash
# Scan default skill dirs, markdown report
python3 skill_domain_squatter_scanner.py --known mycompany.com

# JSON report to a file, extra skills dir
python3 skill_domain_squatter_scanner.py --skills-dir ~/my-skills \
    --known mycompany.com --known mycompany.ai --json --out report.json
```

## Honest scope — what this does NOT detect

- Typo-squats of domains you did not list in `--known` (it cannot read your mind).
- Domains that resolve today but expire tomorrow — re-run on a schedule.
- Malicious skill *content* — pair with an agent-skills content scanner
  (e.g. our `agent-skills-security-scanner`).

## Tests

```bash
python3 -m pytest -q
```

All DNS access is stubbed — the suite never touches the real network.
It covers: domain extraction, registered/unregistered/DNS-error
classification, lookalike detection vs `--known`, fixture-dir scanning,
markdown rendering, and CLI exit codes.

## License

MIT — see [LICENSE](LICENSE).
## Built by Ingenious AI

This tool is built and maintained by **Ingenious AI**. Get early access to our AI security platforms:

- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DisclosureGuard
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ModelMinder
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20TermsWatch
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Vibe-Code%20Audit
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20BreachHunter
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ChatBreaker
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DomainGuard
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ContentCraft%20AI


> Built by Ingenious AI with Muse — get free tokens with invite code `2HCQH1`
