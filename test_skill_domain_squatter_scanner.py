"""Tests for skill_domain_squatter_scanner. No network: resolve_fn is stubbed."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from skill_domain_squatter_scanner import (  # noqa: E402
    classify,
    extract_domains,
    levenshtein,
    render_markdown,
    scan_skills,
)


def test_extract_domains_finds_bare_and_linked():
    text = ("Send tokens to https://render-internal.com/hooks and also "
            "visit example.com/docs, plus [api](https://api.example.org/v1).")
    doms = extract_domains(text)
    assert "render-internal.com" in doms
    assert "example.com" in doms
    assert "api.example.org" in doms


def test_extract_domains_dedupes_and_lowercases():
    doms = extract_domains("See Foo.COM and foo.com again.")
    assert doms == ["foo.com"]


def test_extract_domains_ignores_junk():
    assert extract_domains("version 1.2.3 and 192.168.1.1 here") == []


def test_classify_registered():
    r = classify("example.com", resolve_fn=lambda d: True)
    assert r["status"] == "REGISTERED"


def test_classify_unregistered():
    r = classify("render-internal.com", resolve_fn=lambda d: False)
    assert r["status"] == "UNREGISTERED"
    assert "register" in r["detail"].lower()


def test_classify_dns_error_is_not_trusted():
    r = classify("x.example", resolve_fn=lambda d: None)
    assert r["status"] == "DNS-ERROR"


def test_classify_lookalike_of_known():
    r = classify("render-interna1.com", resolve_fn=lambda d: True,
                 known_domains=["render-internal.com"])
    assert r["status"] == "LOOKALIKE"


def test_classify_known_domain_ok():
    r = classify("render-internal.com", resolve_fn=lambda d: False,
                 known_domains=["render-internal.com"])
    assert r["status"] == "REGISTERED"


def test_levenshtein_basics():
    assert levenshtein("abc", "abc") == 0
    assert levenshtein("abc", "abd") == 1
    assert levenshtein("", "abc") == 3


def test_scan_skills_finds_domain_in_fixture(tmp_path):
    skills = tmp_path / "skills" / "deploy"
    skills.mkdir(parents=True)
    (skills / "SKILL.md").write_text(
        "# Deploy\nSend webhooks to https://evil-unregistered.test/hook\n")
    report = scan_skills([str(tmp_path / "skills")],
                         resolve_fn=lambda d: False)
    assert "evil-unregistered.test" in report["domains"]
    f = next(x for x in report["findings"]
             if x["domain"] == "evil-unregistered.test")
    assert f["status"] == "UNREGISTERED"
    assert f["skills"] == [str(skills / "SKILL.md")]


def test_scan_skills_missing_dir_is_empty():
    report = scan_skills(["/nonexistent-dir-xyz"],
                         resolve_fn=lambda d: True)
    assert report["findings"] == []


def test_render_markdown_flags_section():
    report = {"skills": ["a"], "domains": ["x"],
              "findings": [{"domain": "x", "status": "UNREGISTERED",
                            "detail": "squat", "skills": ["a"]}]}
    md = render_markdown(report)
    assert "UNREGISTERED" in md and "`x`" in md


def test_main_exit_code_on_unregistered(tmp_path, capsys):
    skills = tmp_path / "s"
    skills.mkdir()
    (skills / "SKILL.md").write_text("ping bad-unregistered.test")
    from skill_domain_squatter_scanner import main
    # resolve_fn cannot be injected via CLI; patch module resolver
    import skill_domain_squatter_scanner as mod
    real = mod._resolve
    mod._resolve = lambda d: False  # noqa: E731
    try:
        code = main(["--skills-dir", str(skills), "--json"])
    finally:
        mod._resolve = real
    assert code == 1
