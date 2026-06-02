"""CLI entry point for running the stealth evaluation harness."""
from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console

from nps_lab_el.eval.stealth_metrics import (
    generate_report,
    load_pcap_ip_ids,
    load_pcap_timestamps,
    save_report,
)

console = Console()


@click.command("eval")
@click.option("--fixtures", required=True, type=click.Path(exists=True, file_okay=False), help="Directory containing pcap fixtures.")
@click.option("--baseline", required=True, help="Baseline pcap filename (inside fixtures dir).")
@click.option("--knock", required=True, help="Knock pcap filename (inside fixtures dir).")
@click.option("--out", default="eval/report.json", type=click.Path(), help="Output JSON report path.")
def cli(fixtures: str, baseline: str, knock: str, out: str) -> None:
    """Run the stealth evaluation harness on pcap fixtures."""
    fixtures_dir = Path(fixtures)
    baseline_path = str(fixtures_dir / baseline)
    knock_path = str(fixtures_dir / knock)

    console.print(f"[bold]Loading baseline:[/bold] {baseline_path}")
    baseline_timestamps = load_pcap_timestamps(baseline_path)
    baseline_ip_ids = load_pcap_ip_ids(baseline_path)

    console.print(f"[bold]Loading knock:[/bold] {knock_path}")
    knock_timestamps = load_pcap_timestamps(knock_path)
    knock_ip_ids = load_pcap_ip_ids(knock_path)

    console.print(f"[dim]Baseline: {len(baseline_timestamps)} packets | Knock: {len(knock_timestamps)} packets[/dim]")

    report = generate_report(
        baseline_timestamps=baseline_timestamps,
        knock_timestamps=knock_timestamps,
        baseline_ip_ids=baseline_ip_ids,
        knock_ip_ids=knock_ip_ids,
        replay_reject_rate=0.0,
        decode_accuracy=0.0,
    )

    # Ensure output directory exists
    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    save_report(report, str(out_path))

    console.print(f"\n[bold green]Report saved to {out_path}[/bold green]")
    console.print("[bold]Summary:[/bold]")
    console.print(f"  KS D-statistic:     {report.ks_d_statistic:.4f}")
    console.print(f"  KS p-value:         {report.ks_p_value:.4f}")
    console.print(f"  Entropy (baseline): {report.entropy_baseline:.4f}")
    console.print(f"  Entropy (knock):    {report.entropy_knock:.4f}")
    console.print(f"  Replay reject rate: {report.replay_reject_rate:.4f}")
    console.print(f"  Decode accuracy:    {report.decode_accuracy:.4f}")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
