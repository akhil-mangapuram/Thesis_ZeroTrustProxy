"""
Dedicated Mechanism-Level Ablation Study (Professor Feedback 3)
Evaluates Full Stateful Zero-Trust vs. Stateless-Only Zero-Trust on identical adversarial tool traces.
Performs physical sandbox execution, ground-truth outcome verification, and exact McNemar testing.
"""

import os
import json
import time
from scipy import stats
from sandbox_manager import SandboxManager
from zero_trust_proxy import ZeroTrustProxy
from evaluator import execute_tool_in_sandbox, OutcomeVerifier

def run_ablation():
    traces_path = "evaluation_results/tool_traces.json"
    if not os.path.exists(traces_path):
        print(f"Error: Master trace file '{traces_path}' not found.")
        return

    with open(traces_path, "r", encoding="utf-8") as f:
        all_traces = json.load(f)

    adv_traces = [t for t in all_traces if t.get("type") == "Adversarial"]
    print("=" * 70)
    print("STEP 2.5: DEDICATED MECHANISM ABLATION STUDY (Feedback 3)")
    print("Comparing Full Stateful Zero-Trust vs. Stateless-Only Zero-Trust")
    print(f"Total Adversarial Scenarios Evaluated: n = {len(adv_traces)}")
    print("=" * 70)

    sandbox = SandboxManager()
    
    both_safe = []
    both_comp = []
    stateless_only_safe = []
    stateful_only_safe = [] # c: Stateless compromised, Full Stateful safe

    case_details = []

    for idx, case in enumerate(adv_traces, 1):
        test_id = case["test_id"]
        clearance = case.get("session_clearance", "guest")
        trace = case.get("trace", [])
        category = case.get("category", "")
        
        # 1. Stateless Zero-Trust Replay
        sandbox_path = sandbox.reset_state()
        snap0 = OutcomeVerifier.snapshot_sandbox(sandbox_path)
        p_stateless = ZeroTrustProxy(sandbox, user_clearance=clearance, security_mode="zero_trust", ablation="stateless")
        
        stateless_blocked = False
        stateless_block_reason = ""
        for step in trace:
            tool_name = step["tool"]
            tool_args = step.get("args", {})
            if not p_stateless.evaluate_intent(tool_name, tool_args):
                stateless_blocked = True
                stateless_block_reason = f"Blocked {tool_name}"
                break
            execute_tool_in_sandbox(sandbox.current_sandbox, tool_name, tool_args)
            
        out_stateless = OutcomeVerifier.verify_outcome(
            sandbox.current_sandbox, snap0, case, proxy_blocked=stateless_blocked
        )
        stateless_safe = not out_stateless["physical_compromise"]

        # 2. Full Stateful Zero-Trust Replay
        sandbox_path = sandbox.reset_state()
        snap0 = OutcomeVerifier.snapshot_sandbox(sandbox_path)
        p_full = ZeroTrustProxy(sandbox, user_clearance=clearance, security_mode="zero_trust")
        
        stateful_blocked = False
        stateful_block_reason = ""
        for step in trace:
            tool_name = step["tool"]
            tool_args = step.get("args", {})
            if not p_full.evaluate_intent(tool_name, tool_args):
                stateful_blocked = True
                # Identify which stateful mechanism triggered
                if p_full.session_state.get("session_locked"):
                    stateful_block_reason = "Dynamic Session Lock (Threat Threshold)"
                elif p_full.session_state.get("a3_delete_attempts", 0) > 5:
                    stateful_block_reason = "Cumulative Deletion Rate Limiter (>5 files)"
                elif p_full.session_state.get("external_data_ingested") and tool_name == "write_file":
                    stateful_block_reason = "Post-Ingestion Executable Taint Lock"
                elif p_full.session_state.get("external_data_ingested") and tool_name == "execute_query":
                    stateful_block_reason = "Session Taint Mutation Lock"
                elif p_full.session_state.get("sensitive_data_accessed") and tool_name == "fetch_url":
                    stateful_block_reason = "Cross-Turn Sensitive Data Egress Taint"
                else:
                    stateful_block_reason = f"Stateful Policy Blocked {tool_name}"
                break
            execute_tool_in_sandbox(sandbox.current_sandbox, tool_name, tool_args)

        out_full = OutcomeVerifier.verify_outcome(
            sandbox.current_sandbox, snap0, case, proxy_blocked=stateful_blocked
        )
        stateful_safe = not out_full["physical_compromise"]

        # Categorize into McNemar cells
        if stateless_safe and stateful_safe:
            both_safe.append(test_id)
            pair_type = "a (Both Safe)"
        elif (not stateless_safe) and (not stateful_safe):
            both_comp.append(test_id)
            pair_type = "d (Both Compromised)"
        elif stateless_safe and (not stateful_safe):
            stateless_only_safe.append(test_id)
            pair_type = "b (Stateless Safe only)"
        else: # not stateless_safe and stateful_safe
            stateful_only_safe.append({
                "test_id": test_id,
                "category": category,
                "tool": trace[-1]["tool"] if trace else "N/A",
                "args": trace[-1].get("args", {}) if trace else {},
                "stateless_outcome": out_stateless["outcome_summary"],
                "stateful_mechanism": stateful_block_reason,
                "stateful_outcome": out_full["outcome_summary"]
            })
            pair_type = "c (Stateful Safe only)"

    a = len(both_safe)
    b = len(stateless_only_safe)
    c = len(stateful_only_safe)
    d = len(both_comp)
    n_total = a + b + c + d
    n_discordant = b + c

    # Statistical Tests
    binom_res = stats.binomtest(b, n_discordant, 0.5, alternative="two-sided")
    exact_p = binom_res.pvalue

    chi2 = ((abs(b - c) - 1.0) ** 2) / n_discordant if n_discordant > 0 else 0.0
    asymp_p = stats.chi2.sf(chi2, df=1) if n_discordant > 0 else 1.0

    print("\n" + "=" * 70)
    print("2x2 MATCHED CONTINGENCY TABLE: STATELESS vs. FULL STATEFUL ZERO-TRUST")
    print("=" * 70)
    print(f"Total Adversarial Scenarios (N):       {n_total}")
    print(f"{'':35} Full Zero-Trust Safe    Full Zero-Trust Compromised")
    print(f"  Stateless Zero-Trust Safe          a = {a:<18} b = {b:<18} (Discordant)")
    print(f"  Stateless Zero-Trust Compromised   c = {c:<18} d = {d:<18} (Discordant: c)")
    print("-" * 70)
    print(f"Concordant Pairs (a + d):              {a + d} ({(a + d)/n_total*100:.1f}%)")
    print(f"Discordant Pairs (b, c):               b={b} (Stateless only), c={c} (Full Stateful only)")
    print(f"Exact McNemar Binomial p-value:        p = {exact_p:.6e} ({'Statistically Significant (p < 0.05)' if exact_p < 0.05 else 'Not Significant'})")
    print(f"Edwards' Continuity-Corrected Chi2:    Chi2 = {chi2:.4f}, df = 1, asymptotic p = {asymp_p:.6e}")
    print("=" * 70)

    print("\n" + "#" * 70)
    print(f"DEEP-DIVE: THE {c} DISCORDANT ATTACKS (CAUSAL VALUE OF STATEFUL ENFORCEMENT)")
    print("#" * 70)
    for idx, item in enumerate(stateful_only_safe, 1):
        target_str = item["args"].get("file_path") or item["args"].get("url") or item["args"].get("query") or str(item["args"])
        print(f"\n[{idx}] Test Case: {item['test_id']} (Vector {item['category']})")
        print(f"    Action Attempted:    {item['tool']}({target_str})")
        print(f"    Stateless Posture:   FAILED -> {item['stateless_outcome']}")
        print(f"                         (Stateless rules had no taint history or rate counter)")
        print(f"    Full Stateful Proxy: INTERCEPTED -> {item['stateful_mechanism']}")
        print(f"                         Result: {item['stateful_outcome']}")

    # Export to JSON
    export_data = {
        "evaluation_name": "Mechanism Ablation Study",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "sample_size": n_total,
        "contingency_table": {"a": a, "b": b, "c": c, "d": d},
        "concordant_pairs": a + d,
        "discordant_pairs": {"b": b, "c": c},
        "exact_mcnemar_binomial_p": float(exact_p),
        "continuity_corrected_chi2": float(chi2),
        "asymptotic_chi2_p": float(asymp_p),
        "statistically_significant": bool(exact_p < 0.05),
        "discordant_cases": stateful_only_safe
    }

    out_file = "evaluation_results/ablation_study_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2)

    print(f"\n[EXPORT] Detailed ablation study data saved to: {out_file}")
    print("=" * 70)

if __name__ == "__main__":
    run_ablation()

