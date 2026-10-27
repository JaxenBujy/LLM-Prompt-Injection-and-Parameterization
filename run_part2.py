import payloads as P
from agent import run_agent
from run_trials import run_trials, exfil_succeeded

N = 10
success = lambda out: exfil_succeeded()

CONFIGS = [
    ("(a) No Defense",         P.EXFIL_NAIVE,    False, False, "p2_a"),
    ("(b) Defense A",          P.EXFIL_NAIVE,    True,  False, "p2_b"),
    ("(c) Defense B",          P.EXFIL_NAIVE,    False, True,  "p2_c"),
    ("(d) Adaptive Bypass",    P.BYPASS_SPANISH, True,  True,  "p2_d"),
]

lines = [f"{'Configuration':<24}{'ASR':>6}", "-" * 30]
for label, payload, da, db, prefix in CONFIGS:
    rate = run_trials(
        agent_fn=lambda p, da=da, db=db: run_agent(p, defense_a=da, defense_b=db),
        payload=payload, check=success, n=N, prefix=prefix,
    )
    lines.append(f"{label:<24}{rate:>6.0%}")

table = "\n".join(lines)
print(table)
with open("logs/part2_table.txt", "w", encoding="utf-8") as f:
    f.write(table + "\n")