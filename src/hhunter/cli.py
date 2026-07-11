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
def ingest(path: str) -> None:
    """Zeek conn.log dosyasini oku ve parquet'e cevir. (Hafta 1)"""
    console.print(f"[yellow]TODO:[/] {path} ingestion henuz yazilmadi.")


if __name__ == "__main__":
    app()
