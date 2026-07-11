"""Heartbeat Hunter - Streamlit analiz paneli (demo).

Calistirma:
    pip install -e ".[demo]"
    streamlit run app.py

Girdi: `hhunter score ... -o scored.parquet` ciktisi. Uc gorunum:
1. Adaylar  : huni filtreli siralama tablosu (analistin gunluk av listesi)
2. Kanal    : secilen kanalin zaman cizgisi, aralik dagilimi, periodogrami
              ve alt-skor kirilimi - "skor neden yuksek?" sorusunun cevabi
3. Kampanya : graf katmani - ayni hedefe beacon atan cok-kaynakli desenler

Tasarim notu: panel yalnizca OKUR ve gosterir; tum analiz CLI boru hattinda
yapilir (score -> parquet -> panel). Boylece panel, SIEM'e giden ayni verinin
insan-dostu yuzu olur - ikinci bir hesaplama yolu degil.
"""

import matplotlib

matplotlib.use("Agg")  # headless sunucu/panel icin guvenli backend
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import streamlit as st

from hhunter.campaign import detect_campaigns
from hhunter.features import collapse_bursts, schuster_periodogram
from hhunter.scoring import DEFAULT_WEIGHTS

st.set_page_config(page_title="Heartbeat Hunter", layout="wide")
st.title("Heartbeat Hunter — C2 Beaconing Analiz Paneli")

path = st.sidebar.text_input("Skorlu parquet yolu", "data/ctu42_scored.parquet")


@st.cache_data
def load(p: str) -> pd.DataFrame:
    return pd.read_parquet(p)


@st.cache_data
def campaigns_for(p: str) -> pd.DataFrame:
    """Kampanya tespiti dosya basina bir kez hesaplanir (her rerun'da degil)."""
    return detect_campaigns(load(p))


try:
    df = load(path)
except Exception as exc:  # noqa: BLE001 - kullaniciya ham hata gosterilir
    st.error(f"Dosya okunamadi: {exc}")
    st.stop()

in_scope_only = st.sidebar.checkbox("Sadece kapsam içi (huni filtresi)", value=True)
min_score = st.sidebar.slider("Minimum bileşik skor", 0.0, 1.0, 0.5, 0.05)
top_n = int(st.sidebar.number_input("Listelenecek aday", 10, 5000, 200, 10))

view = df[df["in_scope"]] if (in_scope_only and "in_scope" in df.columns) else df
view = view[view["score"] >= min_score].head(top_n).reset_index(drop=True)
label_col = next((c for c in ("is_cc", "is_beacon", "is_botnet") if c in view.columns), None)

tab_list, tab_detail, tab_camp = st.tabs(["📋 Adaylar", "🔬 Kanal detayı", "🕸️ Kampanyalar"])

with tab_list:
    st.caption(
        f"{len(df):,} çift yüklendi → filtre sonrası {len(view):,} aday. "
        "Skor 'beacon-gibiliği' ölçer; kapsam filtresi C2 arama uzayını daraltır."
    )
    cols = ["score", "src_ip", "dst_ip", "dst_port", "count", "dom_mode", "dst_prevalence"]
    if label_col:
        cols.append(label_col)
    st.dataframe(view[cols].round(3), width="stretch", height=520)

with tab_detail:
    if view.empty:
        st.info("Filtreyi gevşetin — gösterilecek aday yok.")
    else:
        options = [
            f"{r.src_ip} → {r.dst_ip}:{r.dst_port}  (skor {r.score:.3f})"
            for r in view.itertuples()
        ]
        sel = st.selectbox("Kanal seç", range(len(options)), format_func=lambda i: options[i])
        row = view.iloc[sel]
        ts = np.sort(np.asarray(row["timestamps"], dtype=float))
        d = np.diff(ts)

        c1, c2, c3 = st.columns(3)
        c1.metric("Bileşik skor", f"{row['score']:.3f}")
        c2.metric("Tahmini periyot", f"{row['dom_mode']:.1f} sn" if pd.notna(row["dom_mode"]) else "—")
        c3.metric("Bağlantı sayısı", f"{int(row['count']):,}")

        fig, axes = plt.subplots(1, 3, figsize=(14, 3.4))
        axes[0].scatter((ts - ts[0]) / 3600, np.ones_like(ts), s=4, alpha=0.5)
        axes[0].set_title("Zaman çizgisi (saat)")
        axes[0].set_yticks([])
        if len(d):
            axes[1].hist(d[d < np.percentile(d, 99)], bins=60)
        axes[1].set_title("Inter-arrival dağılımı (sn)")
        collapsed = collapse_bursts(ts)
        periods, power = schuster_periodogram(collapsed if len(collapsed) >= 8 else ts)
        if len(power):
            axes[2].semilogx(periods, power, lw=0.8)
        axes[2].set_title("Schuster periodogramı")
        axes[2].set_xlabel("periyot (sn)")
        st.pyplot(fig)
        plt.close(fig)

        sub_cols = [c for c in DEFAULT_WEIGHTS if c in view.columns]
        subs = row[sub_cols].astype(float)
        fig2, ax = plt.subplots(figsize=(8, 2.2))
        ax.barh(sub_cols, subs.fillna(0.0))
        ax.set_xlim(0, 1)
        ax.set_title("Alt-skor kırılımı (NaN = sinyal yok, skora girmez)")
        st.pyplot(fig2)
        plt.close(fig2)

with tab_camp:
    camps = campaigns_for(path)
    if camps.empty:
        st.info(
            "Kampanya adayı yok. Tek enfekte makineli yakalamada (örn. CTU-42) "
            "bu beklenen sonuçtur — katmanın sınavı çok-hostlu senaryodur."
        )
    else:
        st.caption(
            "Kampanya = ≥2 iç kaynağın paylaştığı hedef; periyot tutarlılığı "
            "kampanya/popüler-servis ayrımını yapar."
        )
        show = camps.copy()
        show["sources"] = show["sources"].map(lambda s: ", ".join(s))
        show["ports"] = show["ports"].map(lambda p: ", ".join(map(str, p)))
        st.dataframe(show.round(3), width="stretch", height=520)
