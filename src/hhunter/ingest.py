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


def read_binetflow(path: str | Path) -> pd.DataFrame:
    """CTU-13 .binetflow (Argus bidirectional NetFlow) dosyasini oku.

    Format: CSV, header'li. Ilgili kolonlar:
    StartTime, Dur, Proto, SrcAddr, Sport, Dir, DstAddr, Dport, State,
    sTos, dTos, TotPkts, TotBytes, SrcBytes, Label

    Cikti semasi read_conn_log ile AYNIDIR (ts, src_ip, dst_ip, dst_port,
    duration, orig_bytes) + 'is_botnet' ground-truth etiketi
    (Label kolonunda 'Botnet' gecen satirlar).
    """
    path = Path(path)
    df = pd.read_csv(
        path,
        usecols=["StartTime", "Dur", "SrcAddr", "DstAddr", "Dport", "SrcBytes", "Label"],
        dtype={"Label": "string", "SrcAddr": "string", "DstAddr": "string"},
        low_memory=False,
    )
    # StartTime: '2011/08/10 09:46:53.047277' formatinda -> epoch saniye.
    # DIKKAT: ts.astype("int64") NaT'i NaN degil -9.2e9 cop degere cevirir ve
    # dropna yakalamaz (kod denetiminde bulundu). total_seconds NaT -> NaN yapar.
    ts = pd.to_datetime(df["StartTime"], format="%Y/%m/%d %H:%M:%S.%f", errors="coerce")
    out = pd.DataFrame(
        {
            "ts": (ts - pd.Timestamp(0)).dt.total_seconds(),
            "src_ip": df["SrcAddr"],
            "dst_ip": df["DstAddr"],
            # Dport bazen hex ('0x0303') veya bos gelir
            "dst_port": df["Dport"].map(_parse_port).astype("Int64"),
            "duration": pd.to_numeric(df["Dur"], errors="coerce"),
            "orig_bytes": pd.to_numeric(df["SrcBytes"], errors="coerce"),
            "is_botnet": df["Label"].str.contains("Botnet", case=False, na=False),
            # CC = command & control kanali: beaconing'in asil ground-truth'u.
            # 'Botnet' etiketi spam/DNS/tarama dahil TUM enfekte trafigi kapsar;
            # CC ise sadece C2 kanallarini isaretler (orn. ...-TCP-CC16-HTTP-...)
            "is_cc": df["Label"].str.contains(r"-CC\d*(?:-|$)", regex=True, na=False),
        }
    )
    out = out.dropna(subset=["ts", "src_ip", "dst_ip", "dst_port"])
    return out.sort_values("ts").reset_index(drop=True)


def _parse_port(value: object) -> float:
    """Port degerini parse et: '443', '0x0303', NaN -> float veya NaN."""
    if pd.isna(value):
        return float("nan")
    s = str(value).strip()
    try:
        return float(int(s, 16)) if s.lower().startswith("0x") else float(int(s))
    except ValueError:
        return float("nan")


def group_pairs(df: pd.DataFrame, min_connections: int = 4) -> pd.DataFrame:
    """(src_ip, dst_ip, dst_port) ucluleri icin zaman serilerini cikar.

    min_connections: bundan az baglanti kuran ciftler analiz edilemez
    (2 nokta ile periyodiklik olculmez); varsayilan 4.

    Dondurulen DataFrame: her satir bir cift; 'timestamps' kolonu siralanmis
    ts listesi, 'orig_bytes_list' bayt listesi (Katman 2'de kullanilacak).

    Performans: once ucuz bir sayimla (groupby.size) esigi gecemeyen ciftler
    elenir; pahali liste toplama sadece kalan azinlik icin yapilir. 2.8M akisli
    CTU-13 senaryosunda bu, milyonlarca grubun listeye cevrilmesini onler
    (bellek tasmasi yasandi, bu tasarima gecildi).
    """
    keys = ["src_ip", "dst_ip", "dst_port"]
    counts = df.groupby(keys, observed=True).size()
    eligible = counts[counts >= min_connections].index
    if len(eligible) == 0:
        # Bos donuste de dolu donusle AYNI sema: opsiyonel/etiket kolonlari dahil
        cols = [*keys, "timestamps", "count", "first_seen", "last_seen"]
        cols += [f"{c}_list" for c in ("orig_bytes", "duration") if c in df.columns]
        cols += [c for c in ("is_beacon", "is_botnet", "is_cc") if c in df.columns]
        return pd.DataFrame(columns=cols)
    df = df.set_index(keys).loc[eligible].reset_index()

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
    # Ground-truth etiketler (simulator: is_beacon, CTU-13: is_botnet) —
    # ciftin herhangi bir baglantisi etiketliyse cift etiketlidir
    for label_col in ("is_beacon", "is_botnet", "is_cc"):
        if label_col in df.columns:
            agg[label_col] = (label_col, "any")

    pairs = df.groupby(keys, observed=True).agg(**agg).reset_index()
    return pairs.reset_index(drop=True)
