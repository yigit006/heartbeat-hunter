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


if __name__ == "__main__":
    app()
