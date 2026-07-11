"""CTU-13 binetflow okuyucu testleri (sentetik fixture ile)."""

from pathlib import Path

import pytest

from hhunter.ingest import group_pairs, read_binetflow

BINETFLOW_SAMPLE = """\
StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label
2011/08/10 09:46:53.047277,1.026539,tcp,147.32.84.165,1025,   ->,74.125.232.195,80,SF,0,0,10,1200,600,flow=From-Botnet-V42-TCP-CC
2011/08/10 09:47:53.140000,0.950000,tcp,147.32.84.165,1026,   ->,74.125.232.195,80,SF,0,0,9,1100,590,flow=From-Botnet-V42-TCP-CC
2011/08/10 09:48:53.500000,1.100000,tcp,147.32.84.165,1027,   ->,74.125.232.195,80,SF,0,0,11,1250,610,flow=From-Botnet-V42-TCP-CC
2011/08/10 09:49:52.900000,1.000000,tcp,147.32.84.165,1028,   ->,74.125.232.195,80,SF,0,0,10,1210,605,flow=From-Botnet-V42-TCP-CC
2011/08/10 09:50:10.000000,5.300000,tcp,147.32.84.10,50001,   ->,8.8.8.8,443,SF,0,0,50,60000,20000,flow=Background
2011/08/10 09:51:20.000000,0.001000,udp,147.32.84.11,5060,   ->,10.0.0.1,0x0303,CON,0,0,2,200,100,flow=Background-UDP
2011/08/10 09:52:00.000000,,tcp,147.32.84.12,1111,   ->,1.2.3.4,,S0,0,0,1,60,60,flow=Background
"""


@pytest.fixture
def binetflow(tmp_path: Path) -> Path:
    p = tmp_path / "sample.binetflow"
    p.write_text(BINETFLOW_SAMPLE, encoding="utf-8")
    return p


def test_read_binetflow_schema(binetflow: Path) -> None:
    df = read_binetflow(binetflow)
    assert set(["ts", "src_ip", "dst_ip", "dst_port", "is_botnet"]).issubset(df.columns)
    # Port'u olmayan son satir dusmeli
    assert len(df) == 6
    assert df["ts"].is_monotonic_increasing


def test_botnet_labels(binetflow: Path) -> None:
    df = read_binetflow(binetflow)
    assert df["is_botnet"].sum() == 4
    assert (df[df["is_botnet"]]["src_ip"] == "147.32.84.165").all()


def test_hex_port_parsed(binetflow: Path) -> None:
    df = read_binetflow(binetflow)
    udp_row = df[df["src_ip"] == "147.32.84.11"].iloc[0]
    assert int(udp_row["dst_port"]) == 0x0303  # 771


def test_timestamps_are_epoch(binetflow: Path) -> None:
    df = read_binetflow(binetflow)
    # 2011-08-10 -> epoch ~1.312e9
    assert 1.31e9 < df["ts"].iloc[0] < 1.32e9
    # Beacon araligi ~60sn korunmus mu?
    bot = df[df["is_botnet"]]["ts"].values
    deltas = [b - a for a, b in zip(bot, bot[1:])]
    assert all(55 < d < 65 for d in deltas)


def test_group_pairs_carries_label(binetflow: Path) -> None:
    pairs = group_pairs(read_binetflow(binetflow), min_connections=4)
    assert len(pairs) == 1
    assert bool(pairs.iloc[0]["is_botnet"]) is True
