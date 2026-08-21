import hashlib
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

SEVERITY_WEIGHT = {s: i for i, s in enumerate(SEVERITY_ORDER)}


class Category(Enum):
    WEB = "Web"
    API = "API"
    MOBILE = "Mobile"
    NETWORK = "Network"
    DATABASE = "Database"
    RECON = "Recon"


class Disposition(Enum):
    OPEN = "Açık"
    ACCEPTED_RISK = "Kabul Edilmiş Risk"
    FALSE_POSITIVE = "False Positive"


def _compute_finding_id(category: str, title: str, location: str) -> str:
    """Kategori+baslik+konumdan deterministik bir kimlik uretir -- ayni acik, farkli
    taramalarda hep ayni id'yi alir. Bu, bir bulguyu 'kabul edilmis risk' olarak
    isaretleyip sonraki taramalarda da tanınmasini saglayan mekanizmanin temeli."""
    raw = f"{category}|{title}|{location}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


@dataclass
class Finding:
    title: str
    severity: Severity
    category: Category
    location: str
    description: str
    evidence: str
    remediation: str
    id: str = ""
    disposition: Disposition = Disposition.OPEN
    disposition_reason: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = _compute_finding_id(self.category.value, self.title, self.location)

    @property
    def is_open(self) -> bool:
        return self.disposition == Disposition.OPEN

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "location": self.location,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "disposition": self.disposition.value,
            "disposition_reason": self.disposition_reason,
        }


def sort_findings(findings: list[Finding]) -> list[Finding]:
    # Acik bulgular once, sonra severity'ye gore; incelenmis/kabul edilmisler en sona.
    return sorted(
        findings,
        key=lambda f: (0 if f.is_open else 1, SEVERITY_WEIGHT[f.severity]),
    )


@dataclass
class Verdict:
    status: str  # NOT_READY | READY_WITH_WARNINGS | READY
    label: str
    counts: dict
    accepted_count: int = 0

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "label": self.label,
            "counts": self.counts,
            "accepted_count": self.accepted_count,
        }


def compute_verdict(findings: list[Finding]) -> Verdict:
    """Verdict SADECE 'Açık' (OPEN) bulgulara gore hesaplanir -- 'Kabul Edilmiş Risk' veya
    'False Positive' olarak isaretlenmis bulgular sayima girmez ama raporda gorunmeye
    devam eder (bkz. report/*). Boylece bir bulguyu gerekcesiyle inceleyip kabul etmek
    mumkun, ama gercek/incelenmemis Critical-High bulgular varken verdict asla sessizce
    yesile donmez."""
    open_findings = [f for f in findings if f.is_open]
    accepted_count = len(findings) - len(open_findings)

    counts = {s.value: 0 for s in Severity}
    for f in open_findings:
        counts[f.severity.value] += 1

    if counts[Severity.CRITICAL.value] > 0 or counts[Severity.HIGH.value] > 0:
        status, label = "NOT_READY", "NOT READY FOR PRODUCTION"
    elif counts[Severity.MEDIUM.value] > 0:
        status, label = "READY_WITH_WARNINGS", "READY WITH WARNINGS"
    else:
        status, label = "READY", "READY FOR PRODUCTION"

    return Verdict(status=status, label=label, counts=counts, accepted_count=accepted_count)
