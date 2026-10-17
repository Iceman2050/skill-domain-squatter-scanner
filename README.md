# skill-domain-squatter-scanner

**Agent skills link out to domains — and typosquatters register lookalikes of exactly those domains.**

A skill that tells your agent to visit `githuub.com` instead of `github.com` is a supply-chain attack waiting to happen. This scanner extracts every domain referenced by your skills and classifies it: registered, unregistered, or a lookalike of a domain you own.

## 30-second quickstart
```
python skill_domain_squatter_scanner.py --skills-dir ./skills --json
```

## Example output
```
{
  "skills": ["/tmp/skills2/typosquat-skill/SKILL.md"],
  "domains": ["githuub-typo-squat-zzz.invalid"],
  "findings": [
    {
      "domain": "githuub-typo-squat-zzz.invalid",
      "status": "REGISTERED",
      "detail": "resolves today — re-check on expiry schedule",
      "skills": ["/tmp/skills2/typosquat-skill/SKILL.md"]
    }
  ]
}
```

`--skills-dir` repeatable, `--known` to declare domains you own (lookalike detection is measured against these).

## What it does NOT do
DNS-based classification needs real network — sandboxed/VPN DNS can misreport. Statuses are point-in-time; re-scan on your expiry schedule.

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
