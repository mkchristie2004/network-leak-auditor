from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Iterable, List, Optional


def normalize_domain(domain: str) -> str:
    return domain.strip().lower().strip(".")


@dataclass(frozen=True)
class RuleList:
    name: str
    domains: tuple[str, ...]


@dataclass(frozen=True)
class MatchResult:
    matched_domain: str
    list_name: str


def _parse_domain_lines(lines: Iterable[str]) -> tuple[str, ...]:
    parsed = []
    for line in lines:
        content = line.split("#", 1)[0].strip()
        if not content:
            continue
        parsed.append(normalize_domain(content))
    return tuple(parsed)


def load_domain_file(path: str) -> RuleList:
    file_path = Path(path)
    with file_path.open("r", encoding="utf-8") as handle:
        return RuleList(name=file_path.name, domains=_parse_domain_lines(handle))


def load_bundled_rule_list() -> RuleList:
    resource = resources.files("network_leak_auditor").joinpath("data/trackers.txt")
    with resource.open("r", encoding="utf-8") as handle:
        return RuleList(name="trackers.txt", domains=_parse_domain_lines(handle))


def load_rule_lists(
    list_path: Optional[str] = None, extra_list_paths: Optional[Iterable[str]] = None
) -> List[RuleList]:
    rule_lists = [load_domain_file(list_path)] if list_path else [load_bundled_rule_list()]
    for extra_path in extra_list_paths or []:
        rule_lists.append(load_domain_file(extra_path))
    return rule_lists


class DomainMatcher:
    def __init__(self, rule_lists: Iterable[RuleList]):
        self._rules = [
            (domain, rule_list.name)
            for rule_list in rule_lists
            for domain in rule_list.domains
        ]

    def match(self, domain: Optional[str]) -> Optional[MatchResult]:
        if not domain:
            return None
        candidate = normalize_domain(domain)
        for rule_domain, list_name in self._rules:
            if candidate == rule_domain or candidate.endswith(f".{rule_domain}"):
                return MatchResult(matched_domain=rule_domain, list_name=list_name)
        return None
