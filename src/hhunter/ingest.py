"""Zeek conn.log ingestion: TSV logunu okuyup analiz edilebilir DataFrame'e cevirir.

Zeek TSV formati:
- '#' ile baslayan satirlar metadata'dir. '#fields' satiri kolon adlarini verir.
- Eksik degerler '-' ile gosterilir.
- Zaman damgalari Unix epoch (float saniye).
"""

from pathlib import Path

import pandas as pd

# Analiz icin ihtiyac duydugumuz kolonlar (Zeek adlariyla)
REQUIRED_COLUMNS = ["ts", "id.orig_h", "id.resp_h", "id.resp_p"]
OPTIONAL_COLUMNS = ["duration", "orig_bytes", "resp_bytes", "proto", "conn_state"]

# Kolon adlarindaki '.' pandas'ta sorun cikarir; sadelestiriyoruz
RENAME_MAP = {
    "id.orig_h": "src_ip",
    "id.resp_h": "dst_ip",
    "id.resp_p": "dst_port",
}


def _parse_zeek_fields(path: Path) -> list[str] | None:
    """TSV dosyasinin '#fields' satirindan kolon adlarini cikar."""
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#fields"):
                return line.rstrip("\n").split("\t")[1:]
            if not line.startswith("#"):
                break
    return None


def read_conn_log(path: str | Path) -> pd.DataFrame:
    """Zeek conn.log (TSV) dosyasini oku, temiz bir DataFrame dondur.

    Dondurulen kolonlar: ts, src_ip, dst_ip, dst_port (+ varsa opsiyoneller).
    """
    path = Path(path)
    fields = _parse_zeek_fields(path)
    if fields is None:
        raise ValueError(
            f"{path}: '#fields' satiri bulunamadi - bu bir Zeek TSV conn.log mu?"
        )

    missing = [c for c in REQUIRED_COLUMNS if c not in fields]
    if missing:
        raise ValueError(f"{path}: zorunlu kolonlar eksik: {missing}")

    usecols = [c for c in REQUIRED_COLUMNS + OPTIONAL_COLUMNS if c in fields]
    df = pd.read_csv(
        path,
        sep="\t",
        comment="#",
        names=fields,
        usecols=usecols,
        na_values=["-", "(empty)"],
        low_memory=False,
    )

    df = df.rename(columns=RENAME_MAP)
    df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce").astype("Int64")
    for col in ("duration", "orig_bytes", "resp_bytes"):
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    # Zaman damgasi olmayan satir ise yaramaz
    df = df.dropna(subset=["ts", "src_ip", "dst_ip", "dst_port"])
    return df.sort_values("ts").reset_index(drop=True)


def group_pairs(df: pd.DataFrame, min_connections: int = 4) -> pd.DataFrame:
    """(src_ip, dst_ip, dst_port) ucluleri icin zaman serilerini cikar.

    min_connections: bundan az baglanti kuran ciftler analiz edilemez
    (2 nokta ile periyodiklik olculmez); varsayilan 4.

    Dondurulen DataFrame: her satir bir cift; 'timestamps' kolonu siralanmis
    ts listesi, 'orig_bytes_list' bayt listesi (Katman 2'de kullanilacak).
    """
    agg: dict[str, tuple[str, object]] = {
        "timestamps": ("ts", list),
        "count": ("ts", "size"),
        "first_seen": ("ts", "min"),
        "last_seen": ("ts", "max"),
    }
    if "orig_bytes" in df.columns:
        agg["orig_bytes_list"] = ("orig_bytes", list)
    if "duration" in df.columns:
        agg["duration_list"] = ("duration", list)

    pairs = (
        df.groupby(["src_ip", "dst_ip", "dst_port"], observed=True)
        .agg(**agg)
        .reset_index()
    )
    return pairs[pairs["count"] >= min_connections].reset_index(drop=True)
