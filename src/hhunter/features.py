"""Katman 1: zaman serisi dedektorleri.

CTU-13 dersinden (gunluk Bolum 5): ham inter-arrival CV gercek C2'de calismaz,
cunku beacon'larin arasina burst'ler (art arda hizli istekler) karisir.
Bu modulun uc panzehiri:

1. collapse_bursts: yakin baglantilari tek olaya indir
2. Dayanikli istatistikler: MAD-bazli CV, Bowley skewness (aykiri degere bagisiK)
3. Schuster periodogrami: binleme gerektirmeden, dogrudan olay zamanlarinda
   frekans taramasi - jitter'a ve eksik beacon'a dayanikli
"""

import numpy as np

# Analiz icin cift basina minimum olay sayisi (burst katlama SONRASI)
MIN_EVENTS = 8


def collapse_bursts(ts: np.ndarray, gap: float = 5.0) -> np.ndarray:
    """Birbirine <gap saniye yakin olaylari tek olaya indir (ilkini tut).

    Ornek: beacon her 60sn'de geliyor ama her beacon 3-4 TCP baglantisi
    aciyorsa, ham seri [0, 0.2, 0.5, 60, 60.3, ...] gorunur. Katlama sonrasi
    [0, 60, ...] kalir ve periyot gorunur hale gelir.
    """
    ts = np.sort(np.asarray(ts, dtype=float))
    if len(ts) == 0:
        return ts
    keep = np.ones(len(ts), dtype=bool)
    keep[1:] = np.diff(ts) >= gap
    return ts[keep]


def delta_stats(ts: np.ndarray) -> dict[str, float]:
    """Inter-arrival (ardisik fark) istatistikleri.

    - cv: klasik varyasyon katsayisi (std/mean). Jitter'siz beacon ~0.
    - mad_cv: medyan bazli dayanikli CV = MAD / medyan. Aykiri deger
      (tek uzun sessizlik, tek burst kacagi) CV'yi patlatir ama MAD'i etkilemez.
    - bowley: ceyreklik bazli carpiklik (Q1+Q3-2*Q2)/(Q3-Q1). Simetrik
      dagilimda 0; beacon araliklari simetriktir, insan trafigi sag-carpiktir.
    """
    ts = np.sort(np.asarray(ts, dtype=float))
    d = np.diff(ts)
    d = d[d > 0]
    if len(d) < 3:
        return {"cv": np.nan, "mad_cv": np.nan, "bowley": np.nan, "n_deltas": len(d)}
    q1, q2, q3 = np.percentile(d, [25, 50, 75])
    mad = np.median(np.abs(d - q2))
    iqr = q3 - q1
    return {
        "cv": float(d.std() / d.mean()) if d.mean() > 0 else np.nan,
        "mad_cv": float(mad / q2) if q2 > 0 else np.nan,
        "bowley": float((q1 + q3 - 2 * q2) / iqr) if iqr > 0 else 0.0,
        "n_deltas": len(d),
    }


def dominant_interval(ts: np.ndarray, rel_width: float = 0.25) -> dict[str, float]:
    """Baskin inter-arrival kumesini bul ve o kume icindeki dagilimu olc.

    RITA (activecm) yaklasimindan esinlendi: gercek C2, beacon araliklarinin
    yanina retry/coklu-istek burst'leri karistirir. TUM delta'larin CV'si bu
    yuzden yaniltir (ana CTU-13 C2'sinde 0.47). Cozum: delta'larin log-uzayda
    en yogun modunu bul, sadece o modun etrafindaki (+-rel_width) delta'lara bak.

    Dondurur:
    - dom_mode: baskin aralik (saniye) - tahmini beacon periyodu
    - dom_support: delta'larin ne kadari bu kumede (0-1) - "beacon'in payi"
    - dom_cv: kume ICINDEKI varyasyon katsayisi - dusukse temiz beacon
    """
    d = np.diff(np.sort(np.asarray(ts, dtype=float)))
    d = d[d > 0]
    if len(d) < 5:
        return {"dom_mode": np.nan, "dom_support": np.nan, "dom_cv": np.nan}
    logd = np.log(d)
    nbins = max(10, int(np.sqrt(len(d)) * 2))
    hist, edges = np.histogram(logd, bins=nbins)
    i = int(hist.argmax())
    mode = float(np.exp((edges[i] + edges[i + 1]) / 2))
    mask = np.abs(d - mode) <= rel_width * mode
    cluster = d[mask]
    cv = float(cluster.std() / cluster.mean()) if len(cluster) > 2 and cluster.mean() > 0 else np.nan
    return {"dom_mode": mode, "dom_support": float(mask.mean()), "dom_cv": cv}


def schuster_periodogram(
    ts: np.ndarray,
    min_period: float = 10.0,
    max_period: float | None = None,
    n_periods: int = 2000,
) -> tuple[np.ndarray, np.ndarray]:
    """Olay zamanlarinda Schuster (Rayleigh) periodogrami.

    R(f) = |sum_j exp(2*pi*i*f*t_j)|^2 / n

    Sezgi: her olayi birim cember uzerinde f frekansiyla dondurulmus bir vektor
    olarak dusun. Olaylar f periyoduyla geliyorsa vektorler ayni yonu gosterir
    ve toplamlari buyur; rastgele geliyorsa birbirini yok eder.

    Istatistiksel guzellik: Poisson (rastgele) trafik altinda R ~ Exp(1).
    Yani R=20 gormek, sansla ~exp(-20) olasilikli - neredeyse imkansiz.
    Binleme yok, esit ornekleme varsayimi yok: jitter ve eksik beacon
    sadece tepeyi biraz alcaltir, yok etmez.

    Dondurur: (periods, power) dizileri.
    """
    ts = np.sort(np.asarray(ts, dtype=float))
    n = len(ts)
    if n < 3:
        return np.array([]), np.array([])
    span = ts[-1] - ts[0]
    if max_period is None:
        max_period = span / 4  # guvenilir tespit icin en az ~4 tekrar
    if max_period <= min_period:
        return np.array([]), np.array([])

    periods = np.logspace(np.log10(min_period), np.log10(max_period), n_periods)
    freqs = 1.0 / periods
    # Faz matrisi: (n_periods, n_olay). Buyuk seriler icin parcalayarak hesapla.
    t0 = ts - ts[0]
    power = np.empty(len(freqs))
    chunk = 256
    for i in range(0, len(freqs), chunk):
        f = freqs[i : i + chunk][:, None]
        phases = 2 * np.pi * f * t0[None, :]
        power[i : i + chunk] = (
            np.cos(phases).sum(axis=1) ** 2 + np.sin(phases).sum(axis=1) ** 2
        ) / n
    return periods, power


def _power_at(t0: np.ndarray, periods: np.ndarray) -> np.ndarray:
    """Verilen periyotlarda Schuster gucu."""
    phases = 2 * np.pi * (1.0 / periods)[:, None] * t0[None, :]
    return (np.cos(phases).sum(axis=1) ** 2 + np.sin(phases).sum(axis=1) ** 2) / len(t0)


def _refine_peak(t0: np.ndarray, period: float, rel_width: float = 0.01) -> tuple[float, float]:
    """Kaba izgara tepesinin etrafinda yerel ince arama.

    Neden gerekli: log-izgara noktasi gercek periyottan binde birkac sapsa bile
    uzun kayit boyunca fazlar dagilir ve guc coker. Ince arama bunu duzeltir.
    """
    local = np.linspace(period * (1 - rel_width), period * (1 + rel_width), 400)
    power = _power_at(t0, local)
    i = int(np.argmax(power))
    return float(local[i]), float(power[i])


def periodicity_features(ts: np.ndarray) -> dict[str, float]:
    """Schuster periodogramindan ozet ozellikler.

    - period_est: en guclu periyot (saniye) - ince arama + harmonik duzeltmeli
    - schuster_power: o periyottaki guc. Poisson altinda beklenen maks
      ~ln(n_periods) ~ 7.6; belirgin beacon'da 10x+ gorulur.
    - schuster_sig: cok-deneme duzeltmeli anlamlilik ~ -ln(p-degeri).
      p = 1 - (1 - exp(-R))^n_trials ~ n_trials * exp(-R) kucuk p icin.
    """
    ts = np.sort(np.asarray(ts, dtype=float))
    periods, power = schuster_periodogram(ts)
    if len(power) == 0:
        return {"period_est": np.nan, "schuster_power": np.nan, "schuster_sig": np.nan}
    t0 = ts - ts[0]
    span = float(t0[-1])

    # 1) Kaba tepeyi ince aramayla duzelt
    best_p, best_r = _refine_peak(t0, float(periods[int(np.argmax(power))]))

    # 2) Harmonik tuzagi: mukemmel periyotta T/2, T/3... ayni gucu alir
    # (tarak spektrumu) ve kaba izgara sans eseri bir alt-harmonige kilitlenebilir.
    # Katlari dene: k*P benzer guce ulasiyorsa temel periyot odur.
    # (2T karismaz: alternatif fazlar birbirini sondurur.)
    # Kat bulununca bastan dene: 30 -> 60 -> 120 zinciri ancak boyle kurulur
    # (60'tan 3x=180 denemek 120'yi kacirir).
    promoted = True
    while promoted:
        promoted = False
        for k in (2, 3, 4):
            cand = best_p * k
            if cand > span / 4:
                break
            cp, cr = _refine_peak(t0, cand)
            if cr >= 0.85 * best_r:
                best_p, best_r = cp, max(cr, best_r)
                promoted = True
                break

    r = best_r
    # Bonferroni benzeri duzeltme: bagimsiz deneme sayisini frekans sayisiyla yaklasikla
    log_p = -r + np.log(len(power))  # ln(p) ~ ln(N) - R
    return {
        "period_est": best_p,
        "schuster_power": r,
        "schuster_sig": float(max(0.0, -log_p)),  # buyuk = anlamli
    }


def permutation_significance(
    ts: np.ndarray,
    n_perm: int = 100,
    min_period: float = 10.0,
    max_bins: int = 8192,
    seed: int = 0,
) -> dict[str, float]:
    """BAYWATCH-esini ampirik anlamlilik: varsayimsiz null dagilimi.

    schuster_sig'in Exp(1) esigi Poisson varsayimina dayanir; gercek trafik
    (gunluk ritim, burst) bu varsayimi kirabilir. Cozum (BAYWATCH, DSN 2016):
    olay sayimlarini zaman kovalarina ayir, KOVALARI n_perm kez karistir,
    her karistirmada spektrum tepesini olc. Karistirma kova-sayim marjinalini
    (burst'ler dahil) korur ama kovalarin ZAMANDAKI dizilisini - yani
    periyodikligi - yok eder. Gozlenen tepe null tepelerinden buyukse gercek.

    NEDEN inter-arrival karistirmak DEGIL: beacon'in araliklari zaten hep ~T;
    karistirilmis hali de beacon'dir - test korlesir (ilk denemede yasandi,
    p=0.83 cikti). Periyodiklik burada siralamada degil marjinalde tasinir;
    kova dizilisi ise pozisyon bilgisini tasir ve karistirmayla gercekten olur.

    MALIYET/BINLEME NOTU: Bu fonksiyon binleme kullanir (Schuster'in binlemesiz
    guzelligini kaybeder) - o yuzden birincil dedektor DEGIL, huni mimarisinin
    dogrulama katidir: sadece on-elemeyi gecen adaylara uygulanir.

    Dondurur:
    - perm_pvalue: gozlenen tepeyi asan permutasyon orani (taban 1/n_perm)
    - perm_ratio: gozlenen tepe / null medyani - buyukse guclu sinyal
    """
    ts = np.sort(np.asarray(ts, dtype=float))
    if len(ts) < MIN_EVENTS:
        return {"perm_pvalue": np.nan, "perm_ratio": np.nan}
    span = ts[-1] - ts[0]
    if span <= min_period * 4:
        return {"perm_pvalue": np.nan, "perm_ratio": np.nan}
    # Kova genisligi: min_period'u cozecek kadar ince (T/4), RAM'i asmayacak kadar kaba
    bin_w = max(min_period / 4.0, span / max_bins)
    nbins = int(np.ceil(span / bin_w))
    counts, _ = np.histogram(ts, bins=nbins)
    x = counts - counts.mean()

    def _max_power(sig: np.ndarray) -> float:
        p = np.abs(np.fft.rfft(sig)) ** 2
        return float(p[1:].max())  # DC bileseni haric

    observed = _max_power(x)
    rng = np.random.default_rng(seed)
    null_max = np.array([_max_power(rng.permutation(x)) for _ in range(n_perm)])
    exceed = float((null_max >= observed).mean())
    return {
        "perm_pvalue": max(exceed, 1.0 / n_perm),
        "perm_ratio": observed / float(np.median(null_max)),
    }


def extract_features(ts: np.ndarray, burst_gap: float = 5.0) -> dict[str, float]:
    """Bir ciftin tam ozellik vektoru: ham + burst-katlanmis istatistikler.

    Ham ve katlanmis istatistikleri AYRI tutariz: ikisinin farki bile sinyaldir
    (cok burst'lu ama altta periyodik = tipik gercek C2).
    """
    ts = np.asarray(ts, dtype=float)
    raw = {f"raw_{k}": v for k, v in delta_stats(ts).items()}
    collapsed = collapse_bursts(ts, gap=burst_gap)
    col = {f"col_{k}": v for k, v in delta_stats(collapsed).items()}
    dom = dominant_interval(ts)  # RITA-esini: burst'lu ham seride bile calisir
    per = periodicity_features(collapsed if len(collapsed) >= MIN_EVENTS else ts)
    return {**raw, **col, **dom, **per, "n_events": len(ts), "n_collapsed": len(collapsed)}
