"""Heartbeat Hunter komut satiri arayuzu."""

from typing import Optional

import typer
from rich.console import Console

from hhunter import __version__

app = typer.Typer(help="Heartbeat Hunter - istatistiksel C2 beaconing tespiti")
console = Console()


@app.command()
def version() -> None:
    """Surum bilgisini goster."""
    console.print(f"[bold green]Heartbeat Hunter[/] v{__version__}")


@app.command()
def ingest(
    path: str,
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Parquet cikis yolu"),
    min_connections: int = typer.Option(4, help="Cift basina minimum baglanti sayisi"),
) -> None:
    """Zeek conn.log veya CTU-13 .binetflow dosyasini oku, ciftleri cikar, ozetle."""
    from hhunter.ingest import group_pairs, read_binetflow, read_conn_log

    if path.endswith(".binetflow"):
        df = read_binetflow(path)
    else:
        df = read_conn_log(path)
    pairs = group_pairs(df, min_connections=min_connections)

    console.print(f"[bold]{path}[/] okundu:")
    console.print(f"  Baglanti sayisi : {len(df):,}")
    console.print(f"  Benzersiz kaynak: {df['src_ip'].nunique():,}")
    console.print(f"  Benzersiz hedef : {df['dst_ip'].nunique():,}")
    console.print(f"  Analiz edilebilir cift (>= {min_connections} baglanti): {len(pairs):,}")

    if output:
        pairs.to_parquet(output)
        console.print(f"[green]Yazildi:[/] {output}")


@app.command()
def simulate(
    output: str = typer.Option(..., "--output", "-o", help="Parquet cikis yolu"),
    n_beacons: int = typer.Option(5, help="Beacon (C2) cifti sayisi"),
    n_human: int = typer.Option(50, help="Masum trafik cifti sayisi"),
    hours: float = typer.Option(24.0, help="Simulasyon suresi (saat)"),
    jitter: float = typer.Option(0.1, help="Beacon jitter orani (0.1 = +-%10)"),
    miss_prob: float = typer.Option(0.0, help="Beacon atlama olasiligi"),
    seed: int = typer.Option(42, help="Rastgelelik tohumu (tekrarlanabilirlik)"),
) -> None:
    """Ground-truth etiketli sentetik beacon + insan trafigi uret."""
    from hhunter.simulator import BeaconConfig, generate_dataset

    cfg = BeaconConfig(jitter=jitter, miss_prob=miss_prob)
    df = generate_dataset(
        n_beacons=n_beacons,
        n_human=n_human,
        duration=hours * 3600.0,
        beacon_config=cfg,
        seed=seed,
    )
    df.to_parquet(output)
    n_b = int(df["is_beacon"].sum())
    console.print(
        f"[green]Uretildi:[/] {output} - {len(df):,} baglanti "
        f"({n_b:,} beacon, {len(df) - n_b:,} insan)"
    )


@app.command()
def score(
    path: str,
    top: int = typer.Option(20, help="Listelenecek en supheli kanal sayisi"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Skorlu parquet cikisi"),
    min_connections: int = typer.Option(8, help="Skorlanacak cift icin minimum baglanti"),
    internal_net: list[str] = typer.Option(
        [],
        "--internal-net",
        help="Ic ag CIDR'i (tekrarlanabilir). RFC1918 zaten dahil; kurulusun kamu blogu icin (orn. CTU-13: 147.32.0.0/16)",
    ),
    show_all: bool = typer.Option(
        False,
        "--all",
        help="Kapsam disi ciftleri de listele (ic hedefler, altyapi portlari)",
    ),
    json_out: bool = typer.Option(
        False, "--json", help="Tablo yerine JSON cikti (SIEM/boru hatti entegrasyonu)"
    ),
) -> None:
    """Cift parquet'ini (ingest -o ciktisi) skorla, en supheli kanallari listele.

    Huni mimarisi: skor 'beacon-gibiligi' olcer; kapsam filtresi (dis hedef +
    altyapi-portu-degil) C2 arama uzayini daraltir. Varsayilan liste yalniz
    kapsam ici adaylari gosterir; --all ham siralamayi verir.
    """
    import pandas as pd
    from rich.table import Table

    from hhunter.scoring import score_pairs

    pairs = pd.read_parquet(path)
    pairs = pairs[pairs["count"] >= min_connections]
    scored = score_pairs(pairs, internal_nets=internal_net or None)
    if output:
        scored.to_parquet(output)
        console.print(f"[green]Yazildi:[/] {output}")

    n_total = len(scored)
    if not show_all:
        scored = scored[scored["in_scope"]]

    label_col = next((c for c in ("is_cc", "is_beacon", "is_botnet") if c in scored.columns), None)
    if json_out:
        cols = ["score", "src_ip", "dst_ip", "dst_port", "count", "dom_mode",
                "period_est", "dst_prevalence", "in_scope"]
        if label_col:
            cols.append(label_col)
        print(scored.head(top)[cols].to_json(orient="records", indent=2))
        return

    console.print(
        f"Kapsam filtresi: {n_total:,} cift -> {len(scored):,} aday "
        f"(dis hedef + altyapi-portu-degil){' [--all: filtre kapali]' if show_all else ''}"
    )
    table = Table(title=f"En supheli {top} kanal ({len(scored):,} cift skorlandi)")
    for col in ("skor", "src", "dst", "port", "n", "periyot(sn)", "hedef-yayg.", "etiket"):
        table.add_column(col)
    for _, r in scored.head(top).iterrows():
        table.add_row(
            f"{r['score']:.3f}",
            str(r["src_ip"]),
            str(r["dst_ip"]),
            str(r["dst_port"]),
            str(r["count"]),
            f"{r['dom_mode']:.0f}" if pd.notna(r["dom_mode"]) else "-",
            str(r["dst_prevalence"]),
            ("[red]EVET[/]" if r[label_col] else "-") if label_col else "?",
        )
    console.print(table)


@app.command()
def campaign(
    path: str,
    min_score: float = typer.Option(0.5, help="Kanal icin minimum bilesik skor"),
    min_sources: int = typer.Option(2, help="Kampanya icin minimum ic kaynak sayisi"),
    top: int = typer.Option(20, help="Listelenecek kampanya sayisi"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Kampanya parquet cikisi"),
    json_out: bool = typer.Option(
        False, "--json", help="Tablo yerine JSON cikti (SIEM/boru hatti entegrasyonu)"
    ),
) -> None:
    """Skorlu parquet'ten (score -o ciktisi) kampanya adaylarini cikar.

    Tek beacon anomalidir; ayni hedefe benzer periyotla beacon atan >=2 ic
    makine kampanyadir. Graf katmani, skor katmaninin tek tek zayif buldugu
    kanallari kolektif kanitla yukseltir.
    """
    import pandas as pd
    from rich.table import Table

    from hhunter.campaign import detect_campaigns

    scored = pd.read_parquet(path)
    camps = detect_campaigns(scored, min_score=min_score, min_sources=min_sources)
    if output:
        camps.to_parquet(output)
        console.print(f"[green]Yazildi:[/] {output}")
    if json_out:
        print(camps.head(top).to_json(orient="records", indent=2))
        return
    if camps.empty:
        console.print(
            "Kampanya adayi yok. Not: tek enfekte makineli yakalamada (orn. CTU-42) "
            "bu beklenen sonuctur - katmanin sinavi cok-hostlu senaryodur."
        )
        return

    table = Table(title=f"Kampanya adaylari ({len(camps)})")
    for col in ("kamp.skor", "hedef", "kaynak sayisi", "portlar", "periyot(sn)", "tutarlilik"):
        table.add_column(col)
    for _, r in camps.head(top).iterrows():
        table.add_row(
            f"{r['campaign_score']:.3f}",
            str(r["dst_ip"]),
            str(r["n_sources"]),
            ",".join(str(p) for p in r["ports"]),
            f"{r['period_median']:.0f}" if pd.notna(r["period_median"]) else "-",
            f"{r['period_coherence']:.2f}",
        )
    console.print(table)


if __name__ == "__main__":
    app()
