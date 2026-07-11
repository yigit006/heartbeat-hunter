# Heartbeat Hunter

İstatistiksel temelli C2 beaconing tespit motoru. Zeek `conn.log` verisinden, jitter'lı
komuta-kontrol (C2) trafiğini saf matematikle yakalar: zaman serisi analizi,
olasılıksal skorlama ve graf analizi.

> **Durum:** Aktif geliştirme — Hafta 1/4 (veri boru hattı + beacon simülatörü)

## Neden?

Bir C2 implantı sunucusuna düzenli aralıklarla bağlanır. Saldırganlar bunu gizlemek
için jitter ekler — ama istatistik yalan söylemez. Heartbeat Hunter üç katmanla çalışır:

1. **Zaman serisi analizi** — inter-arrival varyasyon katsayısı, Lomb-Scargle periodogramı
2. **Olasılıksal skorlama** — çoklu sinyalin Bayes yaklaşımıyla birleştirilmesi
3. **Graf analizi** — anomaliden kampanya tespitine

## Kurulum

```bash
pip install -e ".[dev]"
```

## Kullanım

```bash
hhunter --help
```

## Yol Haritası

- [ ] Hafta 1: Zeek conn.log ingestion + beacon simülatörü
- [ ] Hafta 2: Zaman serisi katmanı (CV, MAD, Lomb-Scargle, autocorrelation)
- [ ] Hafta 3: Bayes skorlama + graf analizi (networkx)
- [ ] Hafta 4: CTU-13 değerlendirmesi (precision/recall) + dokümantasyon

## Lisans

MIT
