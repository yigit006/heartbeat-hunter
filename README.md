# Heartbeat Hunter

İstatistiksel temelli C2 beaconing tespit motoru. Zeek `conn.log` verisinden, jitter'lı
komuta-kontrol (C2) trafiğini saf matematikle yakalar: zaman serisi analizi,
olasılıksal skorlama ve graf analizi.

> **Durum:** Aktif geliştirme — Hafta 1/4 (veri boru hattı + beacon simülatörü)

## Neden?

Bir C2 implantı sunucusuna düzenli aralıklarla bağlanır. Saldırganlar bunu gizlemek
için jitter ekler — ama istatistik yalan söylemez. Heartbeat Hunter üç katmanla çalışır:

1. **Zaman serisi analizi** — dayanıklı dağılım istatistikleri (baskın-küme CV, MAD, Bowley skewness) + Schuster/Rayleigh periodogramı
2. **Olasılıksal skorlama** — çoklu sinyalin Bayes yaklaşımıyla birleştirilmesi
3. **Graf analizi** — anomaliden kampanya tespitine

## Yöntem (Katman 1)

Beacon'lar düzenli aralıklarla bağlanır; saldırgan bunu jitter ile gizler.
İki tamamlayıcı yöntem kullanıyoruz:

**Baskın-küme dağılımı** (RITA'dan esinlenildi): gerçek C2 trafiği beacon
aralıklarının arasına retry/çoklu-istek burst'leri karıştırır, bu yüzden ham
varyasyon katsayısı yanıltır. Bunun yerine inter-arrival dağılımının en yoğun
modunu bulup o küme içindeki dağılımı ölçeriz. Ama düşük küme-CV tek başına
yetmez (küme dar tanımlı olduğu için mekanik olarak küçük çıkar) — **küme desteği**
(aralıkların ne kadarının o kümede olduğu) ile birlikte kullanılır.

![Jitter dayanıklılığı](docs/img/jitter_robustness.png)

**Schuster periodogramı**: `R(f) = |Σ exp(2πi·f·tⱼ)|² / n`. Olay zamanlarında
doğrudan frekans taraması — binleme gerektirmez (FFT'nin düzensiz örneklemede
başarısız olduğu yerde çalışır), Poisson gürültüsü altında `R ~ Exp(1)` dağılır,
yani istatistiksel anlamlılık analitik olarak hesaplanır.

![Schuster periodogramı](docs/img/periodogram.png)

CTU-13 Senaryo 42 (Neris) üzerinde: tek özellik C2 kanallarını arka plandan
ayırmaya yetmiyor — bu, Katman 2'nin (çok-sinyal birleşimi) deneysel gerekçesi.

![CTU-13 ayrım](docs/img/ctu_separation.png)

## Kurulum

```bash
pip install -e ".[dev]"
```

## Kullanım

```bash
hhunter --help
```

## Yol Haritası

- [x] Hafta 1: Zeek conn.log ingestion + beacon simülatörü
- [x] Hafta 2: Zaman serisi katmanı (baskın-küme CV, MAD, Bowley, Schuster periodogramı)
- [ ] Hafta 3: Bayes skorlama + graf analizi (networkx)
- [ ] Hafta 4: CTU-13 değerlendirmesi (precision/recall) + dokümantasyon

## Lisans

MIT
