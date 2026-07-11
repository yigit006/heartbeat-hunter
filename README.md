# Heartbeat Hunter

İstatistiksel temelli C2 beaconing tespit motoru. Zeek `conn.log` verisinden, jitter'lı
komuta-kontrol (C2) trafiğini saf matematikle yakalar: zaman serisi analizi,
olasılıksal skorlama ve graf analizi.

> **Durum:** Aktif geliştirme — Hafta 3/4 (Katman 2 bileşik skor + huni mimarisi tamam)

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

## Yöntem (Katman 2): bileşik skor + huni

RITA-esini, etiketsiz çalışan ağırlıklı bileşik skor: zaman alt-skorları
(baskın-küme, MAD, Schuster) + **bayt alt-skorları** (beacon payload'ı sabit
boyutludur — burst zamanlamayı bozar ama baytı bozmaz) + bağlam (hedef
nadirliği, süreklilik, port kategorisi). Anlamlılık, BAYWATCH-esini
kova-permütasyon testiyle ampirik olarak doğrulanır.

Skor tek başına yetmez: CTU-42 sınavında top-20'nin tamamı meşru periyodik
altyapıydı (NTP, SNMP, iç izleme). Literatürün cevabı ağırlık değil **filtre**
(BAYWATCH hunisi, Elastic yön filtresi): skor "beacon-gibiliği" ölçer, kapsam
filtresi (dış hedef + altyapı-portu-değil) C2 arama uzayını daraltır.
Sonuç: 12.220 çift → 4.958 aday; NTP/SNMP listeden temizlendi, dört C2
kanalının tamamı sırada 2-3 kat yükseldi.

```bash
hhunter score pairs.parquet --internal-net 147.32.0.0/16   # kapsam-içi liste
hhunter score pairs.parquet --all                          # ham sıralama
```

## Yöntem (Katman 3): graf — anomaliden kampanyaya

Tek beacon anomalidir; aynı hedefe **benzer periyotla** beacon atan ≥2 iç
makine kampanyadır. Skorlu kanallar iki parçalı grafa (kaynak↔hedef) konur;
paylaşılan hedefler periyot tutarlılığı ve kanal skorlarıyla birleşik
`campaign_score` alır. Dürüst sınır: tek enfekte makineli CTU-42'de bu katman
C2'yi mekanik olarak yakalayamaz (≥2 kaynak şartı) — gerçek sınavı Hafta 4'ün
çok-hostlu senaryoları.

```bash
hhunter campaign scored.parquet          # kampanya adayları
```

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
- [x] Hafta 3: Bileşik skorlama (zaman+bayt+bağlam) + permütasyon anlamlılığı + huni filtresi
- [x] Hafta 3: Graf analizi / kampanya tespiti (networkx) — `hhunter campaign`
- [ ] Hafta 4: Çok-hostlu senaryolar (CTU 9/10/11) — kampanya katmanının gerçek sınavı
- [ ] Hafta 4: CTU-13 değerlendirmesi (precision/recall) + dokümantasyon

## Lisans

MIT
