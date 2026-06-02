from __future__ import annotations

import json
import random
import time
from collections.abc import Callable

import numpy as np
from scipy.stats import ks_2samp

from nps_lab_el.models.auth import EvalReport


def compute_iats(timestamps: list[float]) -> np.ndarray:
    ts = np.array(sorted(timestamps))
    return np.diff(ts)


def ks_test_iats(
    baseline_iats: np.ndarray, knock_iats: np.ndarray
) -> tuple[float, float]:
    stat, p = ks_2samp(baseline_iats, knock_iats)
    return float(stat), float(p)


def shannon_entropy(data: np.ndarray, bins: int = 50) -> float:
    counts, _ = np.histogram(data, bins=bins)
    total = counts.sum()
    if total == 0:
        return 0.0
    probs = counts / total
    probs = probs[probs > 0]
    return float(-np.sum(probs * np.log2(probs)))


def ks_test_ip_ids(
    baseline_ids: list[int], knock_ids: list[int]
) -> tuple[float, float]:
    stat, p = ks_2samp(baseline_ids, knock_ids)
    return float(stat), float(p)


def replay_test(
    token_bits: list[int],
    verify_fn: Callable[[list[int]], bool],
    n_trials: int = 100,
    delay_seconds: float = 0.0,
) -> float:
    rejected = 0
    for _ in range(n_trials):
        if not verify_fn(token_bits):
            rejected += 1
        if delay_seconds > 0:
            time.sleep(delay_seconds)
    return rejected / n_trials


def decode_accuracy_test(
    encode_fn: Callable,
    decode_fn: Callable,
    n_trials: int = 100,
    noise_std: float = 0.005,
) -> float:
    correct = 0
    for _ in range(n_trials):
        bits = [random.randint(0, 1) for _ in range(328)]
        iats = encode_fn(bits)
        noisy_iats = np.array(iats) + np.random.normal(0, noise_std, len(iats))
        decoded = decode_fn(noisy_iats.tolist())
        if decoded == bits:
            correct += 1
    return correct / n_trials


def generate_report(
    baseline_timestamps: list[float],
    knock_timestamps: list[float],
    baseline_ip_ids: list[int],
    knock_ip_ids: list[int],
    replay_reject_rate: float,
    decode_accuracy: float,
) -> EvalReport:
    baseline_iats = compute_iats(baseline_timestamps)
    knock_iats = compute_iats(knock_timestamps)
    ks_d, ks_p = ks_test_iats(baseline_iats, knock_iats)
    ent_baseline = shannon_entropy(baseline_iats)
    ent_knock = shannon_entropy(knock_iats)
    return EvalReport(
        ks_d_statistic=ks_d,
        ks_p_value=ks_p,
        entropy_baseline=ent_baseline,
        entropy_knock=ent_knock,
        replay_reject_rate=replay_reject_rate,
        decode_accuracy=decode_accuracy,
    )


def save_report(report: EvalReport, path: str) -> None:
    with open(path, "w") as f:
        json.dump(report.model_dump(), f, indent=2)


def load_pcap_timestamps(pcap_path: str) -> list[float]:
    from scapy.all import ICMP, rdpcap

    packets = rdpcap(pcap_path)
    timestamps = [
        float(pkt.time) for pkt in packets if pkt.haslayer(ICMP)
    ]
    return sorted(timestamps)


def load_pcap_ip_ids(pcap_path: str) -> list[int]:
    from scapy.all import ICMP, IP, rdpcap

    packets = rdpcap(pcap_path)
    return [
        pkt[IP].id for pkt in packets if pkt.haslayer(ICMP) and pkt.haslayer(IP)
    ]
