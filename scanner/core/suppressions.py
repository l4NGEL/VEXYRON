import json
import os

from core.models import Disposition, Finding

DISPOSITION_ALIASES = {
    "accepted_risk": Disposition.ACCEPTED_RISK,
    "accepted": Disposition.ACCEPTED_RISK,
    "false_positive": Disposition.FALSE_POSITIVE,
    "false-positive": Disposition.FALSE_POSITIVE,
}


def load_suppressions(path: str) -> dict:
    """Bir JSON dosyasindan {finding_id: {disposition, reason}} sozlugu okur. Beklenen
    format:

        [
          {"finding_id": "99265e661f7a", "disposition": "accepted_risk",
           "reason": "...", "reviewed_by": "...", "reviewed_at": "..."}
        ]

    Dosya yoksa/gecersizse sessizce bos sozluk doner -- sert bagimlilik yok, tarama
    suppression dosyasi olmadan da normal sekilde calisir."""
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            entries = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}

    result = {}
    for entry in entries:
        finding_id = entry.get("finding_id")
        reason = entry.get("reason", "").strip()
        if not finding_id or not reason:
            continue  # gerekcesiz bir kabul kaydini yok say -- hesap verebilirlik icin zorunlu
        disposition_key = str(entry.get("disposition", "accepted_risk")).lower()
        disposition = DISPOSITION_ALIASES.get(disposition_key, Disposition.ACCEPTED_RISK)
        result[finding_id] = {"disposition": disposition, "reason": reason}
    return result


def apply_suppressions(findings: list[Finding], suppressions: dict) -> list[Finding]:
    """Her bulgunun id'sini suppressions sozluguyle esler, eslesirse disposition ve
    gerekceyi bulgunun uzerine isler (yerinde degistirir). Eslesmeyen bulgular 'Açık'
    kalir. Ayni listeyi dondurur."""
    if not suppressions:
        return findings
    for f in findings:
        entry = suppressions.get(f.id)
        if entry:
            f.disposition = entry["disposition"]
            f.disposition_reason = entry["reason"]
    return findings
