"""Duman testi: paket kuruluyor ve import ediliyor mu?"""

from hhunter import __version__


def test_version() -> None:
    assert __version__ == "0.1.0"
