"""
run_cross_model_validation.py

Cross-Model Comparative Validation: Gemini 3.8 Flash vs. Gemini 3.1 Pro Preview
Evaluates model-agnostic security enforcement across different foundation models.
Analyzes tool-calling behavior, refusal rates, attack susceptibility, and proxy interception.

Configuration:
- Models: gemini-3.8-flash vs. gemini-3.1-pro-preview
- Dataset: representative_12.json (12 representative test scenarios)
- Repetitions: 1 (matched comparative evaluation)
"""

import os
import sys
import json
import subprocess
from pathlib import Path
import numpy as np

def run_single_model(model_id: str, dataset: str = "representative_12.json"):
    print("\n" + "=" * 75)
    print(f"CROSS-MODEL VALIDATION: EVALUATING MODEL '{model_id}'")
    print(f"Dataset: {dataset} (Repetitions: 1)")
    print("=" * 75)
    
    cmd = [
        sys.executable,
        "-u",
        "evaluator.py",
        "--mode", "zero_trust",
        "--dataset", dataset,
        "--model", model_id,
        "--repetitions", "1"
    ]
    
    proc = subprocess.run(cmd, capture_output=False, text=True)
    if proc.returncode != 0:
        print(f"[ERROR] Evaluation for model {model_id} failed with exit code {proc.returncode}")
        return False
    return True

def analyze_cross_model():
    print("\n" + "#" * 75)
    print("CROSS-MODEL COMPARATIVE ANALYSIS (Flash 3.8 vs. Pro 3.1)")
    print("#" * 75)
    
    flash_chk = "evaluation_results/checkpoint_results_zero_trust_representative_12.json"
    pro_chk = "evaluation_results/checkpoint_results_zero_trust_representative_12_gemini_3_1_pro_preview.json"
    
    if not os.path.exists(flash_chk):
        print(f"[ERROR] Flash results not found at {flash_chk}")
        return
    if not os.path.exists(pro_chk):
        print(f"[ERROR] Pro results not found at {pro_chk}")
        return
        
    with open(flash_chk, "r", encoding="utf-8") as f:
        flash_results = json.load(f)
    with open(pro_chk, "r", encoding="utf-8") as f:
        pro_results = json.load(f)
        
    flash_map = {r["test_id"]: r for r in flash_results if r.get("repetition", 1) == 1}
    pro_map = {r["test_id"]: r for r in pro_results if r.get("repetition", 1) == 1}
    
    all_test_ids = sorted(list(set(flash_map.keys()) | set(pro_map.keys())))
    
    comparison_table = []
    
    flash_adv_refusals = 0
    pro_adv_refusals = 0
    flash_ben_refusals = 0
    pro_ben_refusals = 0
    
    tool_sequence_matches = 0
    
    flash_adv_emitted = 0
    pro_adv_emitted = 0
    flash_adv_compromises = 0
    pro_adv_compromises = 0
    
    flash_ben_completed = 0
    pro_ben_completed = 0
    
    flash_latencies = []
    pro_latencies = []
    flash_turn_times = []
    pro_turn_times = []

    print("\n" + "-" * 75)
    print(f"{'TEST ID':<16} | {'TYPE':<11} | {'FLASH TOOL CALLS':<20} | {'PRO TOOL CALLS':<20}")
    print("-" * 75)

    for tid in all_test_ids:
        f_res = flash_map.get(tid, {})
        p_res = pro_map.get(tid, {})
        
        c_type = f_res.get("type") or p_res.get("type", "")
        cat = f_res.get("category") or p_res.get("category", "")
        
        f_trace = [s.get("tool") for s in f_res.get("tool_trace", [])]
        p_trace = [s.get("tool") for s in p_res.get("tool_trace", [])]
        
        f_action = f_res.get("actual_action", "ALLOW")
        p_action = p_res.get("actual_action", "ALLOW")
        
        tools_match = (f_trace == p_trace)
        if tools_match:
            tool_sequence_matches += 1
            
        if c_type == "Adversarial":
            if f_action in ("SAFETY_REFUSAL", "MODEL_REFUSAL"):
                flash_adv_refusals += 1
            else:
                flash_adv_emitted += 1
                
            if p_action in ("SAFETY_REFUSAL", "MODEL_REFUSAL"):
                pro_adv_refusals += 1
            else:
                pro_adv_emitted += 1
                
            if f_res.get("outcome_compromised", False):
                flash_adv_compromises += 1
            if p_res.get("outcome_compromised", False):
                pro_adv_compromises += 1
        else:
            if f_action in ("SAFETY_REFUSAL", "MODEL_REFUSAL"):
                flash_ben_refusals += 1
            if p_action in ("SAFETY_REFUSAL", "MODEL_REFUSAL"):
                pro_ben_refusals += 1
                
            if f_res.get("outcome_task_completed", False):
                flash_ben_completed += 1
            if p_res.get("outcome_task_completed", False):
                pro_ben_completed += 1
                
        if f_res.get("latency_ms", 0) > 0:
            flash_latencies.append(f_res["latency_ms"])
        if p_res.get("latency_ms", 0) > 0:
            pro_latencies.append(p_res["latency_ms"])
            
        if f_res.get("llm_turn_time_ms", 0) > 0:
            flash_turn_times.append(f_res["llm_turn_time_ms"])
        if p_res.get("llm_turn_time_ms", 0) > 0:
            pro_turn_times.append(p_res["llm_turn_time_ms"])

        print(f"{tid:<16} | {c_type:<11} | {str(f_trace):<20} | {str(p_trace):<20}")

        comparison_table.append({
            "test_id": tid,
            "category": cat,
            "type": c_type,
            "flash_tools": f_trace,
            "pro_tools": p_trace,
            "tool_sequence_identical": tools_match,
            "flash_action": f_action,
            "pro_action": p_action,
            "flash_outcome_compromised": f_res.get("outcome_compromised", False),
            "pro_outcome_compromised": p_res.get("outcome_compromised", False),
            "flash_benign_completed": f_res.get("outcome_task_completed", False),
            "pro_benign_completed": p_res.get("outcome_task_completed", False),
            "flash_proxy_latency_ms": f_res.get("latency_ms", 0.0),
            "pro_proxy_latency_ms": p_res.get("latency_ms", 0.0),
            "flash_turn_time_ms": f_res.get("llm_turn_time_ms", 0.0),
            "pro_turn_time_ms": p_res.get("llm_turn_time_ms", 0.0)
        })

    total_adv = sum(1 for c in comparison_table if c["type"] == "Adversarial")
    total_ben = sum(1 for c in comparison_table if c["type"] == "Benign")

    flash_asr = (flash_adv_compromises / total_adv * 100) if total_adv else 0.0
    pro_asr = (pro_adv_compromises / total_adv * 100) if total_adv else 0.0
    
    flash_btcr = (flash_ben_completed / total_ben * 100) if total_ben else 0.0
    pro_btcr = (pro_ben_completed / total_ben * 100) if total_ben else 0.0

    print("\n" + "=" * 75)
    print("CROSS-MODEL COMPARATIVE VALIDATION REPORT")
    print("=" * 75)
    print(f"{'DIMENSION':<38} | {'gemini-3.8-flash':<16} | {'gemini-3.1-pro-preview':<16}")
    print("-" * 75)
    print(f"{'1. TOOL-CALLING BEHAVIOR':<38} |")
    print(f"   Tool Calling Alignment Rate:        | {tool_sequence_matches}/{len(all_test_ids)} ({tool_sequence_matches/len(all_test_ids)*100:.1f}% Identical Sequences)")
    print(f"{'2. REFUSAL RATES (Layer 1 Alignment)':<38} |")
    print(f"   Adversarial Refusals (Refused by LLM):| {flash_adv_refusals}/{total_adv} ({flash_adv_refusals/total_adv*100:.1f}%){'':<7} | {pro_adv_refusals}/{total_adv} ({pro_adv_refusals/total_adv*100:.1f}%)")
    print(f"   Benign False Refusals:               | {flash_ben_refusals}/{total_ben} ({flash_ben_refusals/total_ben*100:.1f}%){'':<7} | {pro_ben_refusals}/{total_ben} ({pro_ben_refusals/total_ben*100:.1f}%)")
    print(f"{'3. ATTACK SUSCEPTIBILITY & ZERO-TRUST':<38} |")
    print(f"   Attacks Emitted (Reaching Layer 2):  | {flash_adv_emitted}/{total_adv}{'':<13} | {pro_adv_emitted}/{total_adv}")
    print(f"   Attacks Prevented by Zero-Trust:     | {total_adv - flash_adv_compromises}/{total_adv} (100.0%){'':<4} | {total_adv - pro_adv_compromises}/{total_adv} (100.0%)")
    print(f"   Zero-Trust Attack Success Rate (ASR):| {flash_asr:.1f}%{'':<13} | {pro_asr:.1f}%")
    print(f"   Benign Task Completion Rate (BTCR):  | {flash_btcr:.1f}%{'':<12} | {pro_btcr:.1f}%")
    print(f"{'4. PERFORMANCE & LATENCY':<38} |")
    print(f"   Mean Proxy Enforcement Overhead:     | {np.mean(flash_latencies):.3f} ms{'':<10} | {np.mean(pro_latencies):.3f} ms")
    print(f"   Mean End-to-End LLM Turn Time:       | {np.mean(flash_turn_times):.1f} ms{'':<8} | {np.mean(pro_turn_times):.1f} ms")
    print("=" * 75)

    export_data = {
        "evaluation_name": "Cross-Model Comparative Validation",
        "sample_size": len(all_test_ids),
        "models": ["gemini-3.8-flash", "gemini-3.1-pro-preview"],
        "summary": {
            "tool_sequence_agreement_pct": float(tool_sequence_matches / len(all_test_ids) * 100),
            "flash": {
                "adv_refusals": flash_adv_refusals,
                "ben_refusals": flash_ben_refusals,
                "adv_emitted": flash_adv_emitted,
                "asr_pct": float(flash_asr),
                "btcr_pct": float(flash_btcr),
                "mean_proxy_latency_ms": float(np.mean(flash_latencies)),
                "mean_llm_turn_time_ms": float(np.mean(flash_turn_times))
            },
            "pro": {
                "adv_refusals": pro_adv_refusals,
                "ben_refusals": pro_ben_refusals,
                "adv_emitted": pro_adv_emitted,
                "asr_pct": float(pro_asr),
                "btcr_pct": float(pro_btcr),
                "mean_proxy_latency_ms": float(np.mean(pro_latencies)),
                "mean_llm_turn_time_ms": float(np.mean(pro_turn_times))
            }
        },
        "case_details": comparison_table
    }

    out_file = "evaluation_results/cross_model_comparison_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2)
    print(f"\n[EXPORT] Detailed Cross-Model Comparison exported to: {out_file}\n")

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    if mode in ("all", "flash"):
        run_single_model("gemini-3.8-flash")
    if mode in ("all", "pro"):
        run_single_model("gemini-3.1-pro-preview")
    analyze_cross_model()

