"""Ingestion testleri: Zeek TSV parse + cift gruplama."""

from pathlib import Path

import pytest

from hhunter.ingest import group_pairs, read_conn_log

# Gercek Zeek conn.log formatinda mini fixture:
# - 10.0.0.5 -> 203.0.113.7:443 : 5 baglanti, ~60sn arayla (beacon benzeri)
# - 10.0.0.9 -> 198.51.100.3:80 : 2 baglanti (min_connections altinda, elenmeli)
# - '-' eksik deger ornekleri icerir
ZEEK_SAMPLE = """\
#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tconn
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_bytes\tresp_bytes\tconn_state
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tinterval\tcount\tcount\tstring
1600000000.000000\tC1\t10.0.0.5\t50001\t203.0.113.7\t443\ttcp\t0.5\t120\t340\tSF
1600000060.100000\tC2\t10.0.0.5\t50002\t203.0.113.7\t443\ttcp\t0.4\t118\t338\tSF
1600000119.900000\tC3\t10.0.0.5\t50003\t203.0.113.7\t443\ttcp\t0.6\t121\t341\tSF
1600000180.200000\tC4\t10.0.0.5\t50004\t203.0.113.7\t443\ttcp\t0.5\t119\t339\tSF
1600000240.000000\tC5\t10.0.0.5\t50005\t203.0.113.7\t443\ttcp\t-\t120\t-\tSF
1600000010.000000\tC6\t10.0.0.9\t50100\t198.51.100.3\t80\ttcp\t1.2\t500\t9000\tSF
1600000900.000000\tC7\t10.0.0.9\t50101\t198.51.100.3\t80\ttcp\t2.3\t600\t12000\tSF
"""


@pytest.fixture
def conn_log(tmp_path: Path) -> Path:
    p = tmp_path / "conn.log"
    p.write_text(ZEEK_SAMPLE, encoding="utf-8")
    return p


def test_read_conn_log(conn_log: Path) -> None:
    df = read_conn_log(conn_log)
    assert len(df) == 7
    assert set(["ts", "src_ip", "dst_ip", "dst_port"]).issubset(df.columns)
    assert df["ts"].is_monotonic_increasing
    # '-' eksik deger olarak parse edilmeli
    assert df["duration"].isna().sum() == 1


def test_group_pairs_filters_small(conn_log: Path) -> None:
    pairs = group_pairs(read_conn_log(conn_log), min_connections=4)
    assert len(pairs) == 1  # 2 baglantili cift elendi
    row = pairs.iloc[0]
    assert row["src_ip"] == "10.0.0.5"
    assert row["dst_ip"] == "203.0.113.7"
    assert row["count"] == 5
    assert len(row["timestamps"]) == 5
    # Beacon benzeri: araliklar ~60sn
    ts = row["timestamps"]
    deltas = [b - a for a, b in zip(ts, ts[1:])]
    assert all(55 < d < 65 for d in deltas)


def test_missing_fields_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.log"
    p.write_text("no zeek header here\n", encoding="utf-8")
    with pytest.raises(ValueError, match="#fields"):
        read_conn_log(p)
