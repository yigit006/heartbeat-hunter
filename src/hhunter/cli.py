"""Heartbeat Hunter komut satiri arayuzu."""

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
    output: str = typer.Option(None, "--output", "-o", help="Parquet cikis yolu"),
    min_connections: int = typer.Option(4, help="Cift basina minimum baglanti sayisi"),
) -> None:
    """Zeek conn.log dosyasini oku, ciftleri cikar, ozetle."""
    from hhunter.ingest import group_pairs, read_conn_log

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


if __name__ == "__main__":
    app()
