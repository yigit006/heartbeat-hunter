"""CLI entegrasyon testleri: score/campaign --json (SIEM boru hatti sozlesmesi)."""

import json

import numpy as np
import pandas as pd
from typer.testing import CliRunner

from hhunter.cli import app

runner = CliRunner()


def _pairs_parquet(tmp_path) -> str:
    """Kucuk sentetik cift dosyasi: 2 temiz beacon ayni dis hedefe + 1 tekil."""
    base = np.arange(0, 6 * 3600, 60.0)
    rows = [
        ("10.0.0.1", "93.184.216.34", 443),
        ("10.0.0.2", "93.184.216.34", 443),
        ("10.0.0.3", "198.51.100.9", 888),
    ]
    pairs = pd.DataFrame(
        {
            "src_ip": [r[0] for r in rows],
            "dst_ip": [r[1] for r in rows],
            "dst_port": [r[2] for r in rows],
            "timestamps": [base] * len(rows),
            "count": [len(base)] * len(rows),
            "first_seen": [base[0]] * len(rows),
            "last_seen": [base[-1]] * len(rows),
        }
    )
    p = str(tmp_path / "pairs.parquet")
    pairs.to_parquet(p)
    return p


def test_score_json_output(tmp_path) -> None:
    p = _pairs_parquet(tmp_path)
    res = runner.invoke(app, ["score", p, "--json", "-o", str(tmp_path / "scored.parquet")])
    assert res.exit_code == 0, res.output
    # "Yazildi:" satirindan sonra saf JSON gelir; JSON'i koseli parantezden yakala
    payload = res.output[res.output.index("[") :]
    records = json.loads(payload)
    assert len(records) >= 1
    for key in ("score", "src_ip", "dst_ip", "dst_port", "in_scope"):
        assert key in records[0]


def test_campaign_json_output(tmp_path) -> None:
    p = _pairs_parquet(tmp_path)
    scored = str(tmp_path / "scored.parquet")
    runner.invoke(app, ["score", p, "--json", "-o", scored])
    res = runner.invoke(app, ["campaign", scored, "--json"])
    assert res.exit_code == 0, res.output
    records = json.loads(res.output[res.output.index("[") :])
    # 2 kaynak ayni dis hedefe ayni periyotla -> 1 kampanya
    assert len(records) == 1
    assert records[0]["dst_ip"] == "93.184.216.34"
    assert records[0]["n_sources"] == 2
