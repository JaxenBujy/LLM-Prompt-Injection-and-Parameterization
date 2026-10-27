import payloads as P
from defenses import blocked_terms

cases = {
    "EXFIL_NAIVE": P.EXFIL_NAIVE,
    "BYPASS_PARAPHRASE": P.BYPASS_PARAPHRASE,
    "BYPASS_SPANISH": P.BYPASS_SPANISH,
    "BYPASS_ROT13": P.BYPASS_ROT13,
    "BYPASS_BASE64": P.BYPASS_BASE64,
}
for name, text in cases.items():
    hits = blocked_terms(text)
    print(f"{name:<18} {'BLOCKED ' + str(hits) if hits else 'passes filter'}")