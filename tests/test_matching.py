from network_leak_auditor.matching import DomainMatcher, RuleList, load_domain_file


def test_domain_matcher_supports_exact_and_suffix_matches():
    matcher = DomainMatcher([RuleList(name="starter", domains=("example.com", "tracker.net"))])

    exact = matcher.match("example.com")
    suffix = matcher.match("a.b.example.com")

    assert exact is not None and exact.matched_domain == "example.com"
    assert suffix is not None and suffix.matched_domain == "example.com"
    assert matcher.match("not-example.org") is None


def test_load_domain_file_ignores_comments_blanks_and_case(tmp_path):
    rule_file = tmp_path / "custom.txt"
    rule_file.write_text(
        "\n# comment\nExample.COM\nsubdomain.example.org  # inline comment\n\n",
        encoding="utf-8",
    )

    rule_list = load_domain_file(str(rule_file))

    assert rule_list.name == "custom.txt"
    assert rule_list.domains == ("example.com", "subdomain.example.org")
