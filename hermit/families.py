"""A readable malware-family label for a rule, for grouping in reports and the GUI.

Uses the rule's own metadata when it has a family field, otherwise reads it from the name:
`DITEKSHEN_MALWARE_Win_Steamhook` -> Steamhook, `MALPEDIA_Win_Taleret_Auto` -> Taleret,
`SIGNATURE_BASE_MAL_LummaC2_Stealer_Jan24` -> LummaC2.
"""
from __future__ import annotations

import re

# Repository prefixes YARA Forge adds, and words that describe a rule rather than name a family.
_REPO = ("signature_base_", "ditekshen_", "malpedia_", "sekoia_", "elastic_", "reversinglabs_",
         "gcti_", "fireeye_rt_", "avastti_", "volexity_", "eset_", "cape_", "capev2_", "deadbits_",
         "embeeresearch_", "jpcert_", "trellix_arc_", "telekom_security_", "harfanglab_", "delivr_to_",
         "arkbird_solg_", "rapid7_", "withsecure_", "dragonthreatlabs_", "stairwell_", "bitdefender_",
         "threatfox_", "infosec_", "certpl_", "binaryalert_", "trellix_", "jeff_", "russianpanda_")
_NOISE = {
    "mal", "malware", "apt", "crime", "susp", "suspicious", "hktl", "hacktool", "pua", "pup", "vuln", "info",
    "gen", "generic", "indicator", "tool", "tools", "win", "win32", "win64", "windows", "elf", "linux",
    "lnx", "osx", "macos", "mac", "android", "multi", "pe", "dotnet", "net", "msil", "js", "ps1", "script",
    "trojan", "backdoor", "loader", "dropper", "downloader", "stealer", "infostealer", "ransomware",
    "ransom", "rat", "bot", "miner", "coinminer", "worm", "exploit", "expl", "webshell", "example",
    "auto", "strings", "string", "detect", "detection", "rule", "sig", "file", "payload", "config",
    "x86", "x64", "a", "b", "c", "v1", "v2", "v3", "mem", "memory", "unpacked", "packed",
}
_MONTH = re.compile(r"^(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\d{0,4}$", re.I)


def family_of(name: str, meta: dict | None = None) -> str:
    meta = meta or {}
    for k in ("malware_family", "family", "malware"):
        v = str(meta.get(k, "")).strip()
        if v and len(v) <= 40 and v.lower() not in _NOISE:
            return v.split(",")[0].strip()
    low = name.lower()
    for p in _REPO:
        if low.startswith(p):
            name, low = name[len(p):], low[len(p):]
            break
    if low.startswith(("cert_blocklist", "certificate_")):
        return "Abused certificates"
    words: list[str] = []
    for part in name.split("_"):
        pl = part.lower()
        useful = part and pl not in _NOISE and not _MONTH.match(pl) and not pl.isdigit() \
            and not re.fullmatch(r"[0-9a-f]{6,}", pl)
        if useful:
            words.append(part)
            if len(words) == 2:
                break
        elif words:
            break
    return " ".join(words) if words else "Other"
