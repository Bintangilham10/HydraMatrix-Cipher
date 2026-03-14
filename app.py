"""
HydraMatrix Cipher - Interactive Web Application
==================================================

Aplikasi web interaktif menggunakan Streamlit untuk:
1. Enkripsi / Dekripsi Teks
2. Enkripsi / Dekripsi File
3. Visualisasi Proses Enkripsi
4. Analisis & Pengujian (Avalanche Effect, Performance)

Jalankan: streamlit run app.py
"""

import streamlit as st
import time
import io
import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
import numpy as np

matplotlib.use("Agg")

# Tambahkan parent directory ke path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hydra_cipher.core import HydraMatrixCipher
from hydra_cipher.utils import hamming_distance, hex_format, BLOCK_SIZE
from tests.test_avalanche import (
    analyze_plaintext_avalanche,
    analyze_key_avalanche,
)
from tests.test_performance import benchmark_encryption

# ============================================================
# Konfigurasi Halaman
# ============================================================

st.set_page_config(
    page_title="HydraMatrix Cipher",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# Custom CSS
# ============================================================

st.markdown("""
<style>
    /* ---- Global ---- */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    .stApp {
        font-family: 'Inter', sans-serif;
    }

    /* ---- Header ---- */
    .hero-title {
        font-size: 2.6rem;
        font-weight: 800;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        margin-bottom: 0;
        letter-spacing: -0.5px;
    }
    .hero-subtitle {
        font-size: 1rem;
        color: #94a3b8;
        text-align: center;
        margin-top: 4px;
        margin-bottom: 28px;
        font-weight: 400;
    }

    /* ---- Cards ---- */
    .metric-card {
        background: linear-gradient(135deg, #1e1b4b 0%, #312e81 100%);
        border: 1px solid rgba(139, 92, 246, 0.3);
        border-radius: 16px;
        padding: 20px 24px;
        margin-bottom: 16px;
        box-shadow: 0 4px 24px rgba(99, 102, 241, 0.12);
    }
    .metric-card h3 {
        color: #c4b5fd;
        font-size: 0.82rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 1.2px;
        margin-bottom: 6px;
    }
    .metric-card .value {
        color: #f8fafc;
        font-size: 1.7rem;
        font-weight: 700;
    }
    .metric-card .sub {
        color: #94a3b8;
        font-size: 0.78rem;
        margin-top: 4px;
    }

    /* ---- Result box ---- */
    .result-box {
        background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
        border: 1px solid rgba(139, 92, 246, 0.35);
        border-radius: 14px;
        padding: 20px 24px;
        margin: 12px 0;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.88rem;
        color: #e2e8f0;
        word-wrap: break-word;
        overflow-wrap: break-word;
        line-height: 1.7;
        box-shadow: 0 4px 20px rgba(0,0,0,0.25);
    }
    .result-box .label {
        color: #a78bfa;
        font-weight: 600;
        font-size: 0.78rem;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-bottom: 8px;
        display: block;
    }

    /* ---- Process step ---- */
    .process-step {
        background: rgba(30, 27, 75, 0.55);
        border-left: 3px solid #8b5cf6;
        padding: 12px 18px;
        margin: 8px 0;
        border-radius: 0 10px 10px 0;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
        color: #cbd5e1;
    }
    .process-step .step-label {
        color: #a78bfa;
        font-weight: 600;
        font-size: 0.72rem;
        text-transform: uppercase;
        letter-spacing: 0.8px;
    }

    /* ---- Info banner ---- */
    .info-banner {
        background: linear-gradient(135deg, #1e3a5f 0%, #1e1b4b 100%);
        border: 1px solid rgba(56, 189, 248, 0.3);
        border-radius: 14px;
        padding: 18px 22px;
        margin: 12px 0;
        color: #e2e8f0;
        font-size: 0.88rem;
    }
    .info-banner .banner-title {
        color: #38bdf8;
        font-weight: 700;
        font-size: 0.95rem;
        margin-bottom: 8px;
    }

    /* ---- Sidebar ---- */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0f0c29 0%, #1e1b4b 50%, #24243e 100%);
    }
    section[data-testid="stSidebar"] .stMarkdown h1,
    section[data-testid="stSidebar"] .stMarkdown h2,
    section[data-testid="stSidebar"] .stMarkdown h3 {
        color: #c4b5fd;
    }
    section[data-testid="stSidebar"] .stMarkdown p,
    section[data-testid="stSidebar"] .stMarkdown li {
        color: #cbd5e1;
    }

    /* ---- Tabs ---- */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 10px;
        padding: 10px 22px;
        font-weight: 600;
    }

    /* ---- Table styling ---- */
    .stDataFrame {
        border-radius: 12px;
        overflow: hidden;
    }
</style>
""", unsafe_allow_html=True)


# ============================================================
# Sidebar
# ============================================================

with st.sidebar:
    st.markdown("## 🔐 HydraMatrix Cipher")
    st.markdown("""
    **Algoritma Enkripsi Simetris Custom**

    Menggabungkan:
    - 🔀 Dynamic S-Box (key-dependent)
    - 📊 Matrix Transposition
    - 🔄 Bitwise Feedback Key Schedule

    ---

    **Spesifikasi:**
    - Block: 128-bit
    - Key: 128-bit
    - Rounds: 10

    ---

    **Komponen Algoritma:**
    1. SubBytes (Substitusi)
    2. ShiftRows (Transposisi)
    3. MixColumns (Difusi GF(2⁸))
    4. AddRoundKey (Key Mixing)

    ---
    *Dibuat untuk tugas Kriptografi*
    """)


# ============================================================
# Header
# ============================================================

st.markdown('<h1 class="hero-title">🐉 HydraMatrix Cipher</h1>', unsafe_allow_html=True)
st.markdown(
    '<p class="hero-subtitle">Custom Symmetric Block Cipher — '
    'Dynamic S-Box · Matrix Transposition · Bitwise Feedback Key Schedule</p>',
    unsafe_allow_html=True,
)


# ============================================================
# Utility Functions
# ============================================================

def validate_key(key_str: str) -> tuple:
    """Validasi dan konversi input key. Return (key_bytes, error_msg)."""
    if not key_str:
        return None, "Kunci tidak boleh kosong"

    key_bytes = key_str.encode("utf-8")
    if len(key_bytes) < BLOCK_SIZE:
        key_bytes = key_bytes.ljust(BLOCK_SIZE, b"\x00")
    elif len(key_bytes) > BLOCK_SIZE:
        key_bytes = key_bytes[:BLOCK_SIZE]

    return key_bytes, None


def create_metric_card(title: str, value: str, subtitle: str = "") -> str:
    """Buat HTML metric card."""
    sub_html = f'<div class="sub">{subtitle}</div>' if subtitle else ""
    return f"""
    <div class="metric-card">
        <h3>{title}</h3>
        <div class="value">{value}</div>
        {sub_html}
    </div>
    """


# ============================================================
# Tab Layout
# ============================================================

tab_encrypt, tab_file, tab_visual, tab_analysis = st.tabs([
    "🔒 Enkripsi / Dekripsi Teks",
    "📁 Enkripsi / Dekripsi File",
    "🔍 Visualisasi Proses",
    "📊 Analisis & Pengujian",
])


# ============================================================
# TAB 1: Enkripsi / Dekripsi Teks
# ============================================================

with tab_encrypt:
    st.markdown("### 🔒 Enkripsi & Dekripsi Teks")

    col_input, col_output = st.columns(2)

    with col_input:
        st.markdown("#### Input")
        key_input = st.text_input(
            "🔑 Kunci Enkripsi (16 karakter)",
            value="HydraMatrix!2026",
            max_chars=32,
            key="text_key",
            help="Kunci akan di-pad/truncate ke 16 bytes",
        )

        mode = st.radio(
            "Mode:",
            ["Enkripsi", "Dekripsi"],
            horizontal=True,
            key="text_mode",
        )

        if mode == "Enkripsi":
            input_text = st.text_area(
                "📝 Plaintext",
                value="Hello, HydraMatrix Cipher!",
                height=150,
                key="plaintext_input",
            )
        else:
            input_text = st.text_area(
                "🔐 Ciphertext (hex)",
                height=150,
                key="ciphertext_input",
                help="Masukkan ciphertext dalam format hexadecimal",
            )

        process_btn = st.button(
            f"⚡ {'Enkripsi' if mode == 'Enkripsi' else 'Dekripsi'} Sekarang",
            type="primary",
            use_container_width=True,
            key="text_process_btn",
        )

    with col_output:
        st.markdown("#### Output")

        if process_btn and input_text:
            key_bytes, key_error = validate_key(key_input)

            if key_error:
                st.error(f"❌ {key_error}")
            else:
                try:
                    cipher = HydraMatrixCipher(key_bytes)
                    start_time = time.perf_counter()

                    if mode == "Enkripsi":
                        plaintext_bytes = input_text.encode("utf-8")
                        ciphertext = cipher.encrypt(plaintext_bytes)
                        elapsed = time.perf_counter() - start_time

                        ct_hex = ciphertext.hex()

                        st.markdown(
                            f'<div class="result-box">'
                            f'<span class="label">Ciphertext (Hex)</span>'
                            f'{ct_hex}'
                            f'</div>',
                            unsafe_allow_html=True,
                        )

                        col_m1, col_m2, col_m3 = st.columns(3)
                        with col_m1:
                            st.markdown(
                                create_metric_card(
                                    "Input Size",
                                    f"{len(plaintext_bytes)} B",
                                    f"{len(plaintext_bytes) * 8} bits",
                                ),
                                unsafe_allow_html=True,
                            )
                        with col_m2:
                            st.markdown(
                                create_metric_card(
                                    "Output Size",
                                    f"{len(ciphertext)} B",
                                    f"{len(ciphertext) * 8} bits",
                                ),
                                unsafe_allow_html=True,
                            )
                        with col_m3:
                            st.markdown(
                                create_metric_card(
                                    "Waktu",
                                    f"{elapsed * 1000:.2f} ms",
                                    "encryption time",
                                ),
                                unsafe_allow_html=True,
                            )

                        # Simpan untuk copy
                        st.code(ct_hex, language=None)

                    else:  # Dekripsi
                        try:
                            ct_bytes = bytes.fromhex(input_text.strip())
                        except ValueError:
                            st.error("❌ Format hex tidak valid!")
                            st.stop()

                        plaintext = cipher.decrypt(ct_bytes)
                        elapsed = time.perf_counter() - start_time

                        try:
                            pt_str = plaintext.decode("utf-8")
                        except UnicodeDecodeError:
                            pt_str = repr(plaintext)

                        st.markdown(
                            f'<div class="result-box">'
                            f'<span class="label">Plaintext</span>'
                            f'{pt_str}'
                            f'</div>',
                            unsafe_allow_html=True,
                        )

                        col_m1, col_m2 = st.columns(2)
                        with col_m1:
                            st.markdown(
                                create_metric_card(
                                    "Output Size",
                                    f"{len(plaintext)} B",
                                ),
                                unsafe_allow_html=True,
                            )
                        with col_m2:
                            st.markdown(
                                create_metric_card(
                                    "Waktu",
                                    f"{elapsed * 1000:.2f} ms",
                                    "decryption time",
                                ),
                                unsafe_allow_html=True,
                            )

                except Exception as e:
                    st.error(f"❌ Error: {str(e)}")

        elif process_btn:
            st.warning("⚠️ Masukkan teks terlebih dahulu!")


# ============================================================
# TAB 2: Enkripsi / Dekripsi File
# ============================================================

with tab_file:
    st.markdown("### 📁 Enkripsi & Dekripsi File")

    col_f1, col_f2 = st.columns(2)

    with col_f1:
        file_key = st.text_input(
            "🔑 Kunci Enkripsi (16 karakter)",
            value="HydraMatrix!2026",
            max_chars=32,
            key="file_key",
        )

        file_mode = st.radio(
            "Mode:", ["Enkripsi File", "Dekripsi File"],
            horizontal=True,
            key="file_mode",
        )

        uploaded_file = st.file_uploader(
            "📎 Pilih file",
            key="file_upload",
            help="Upload file untuk dienkripsi/didekripsi",
        )

    with col_f2:
        if uploaded_file is not None:
            file_data = uploaded_file.read()
            key_bytes, key_error = validate_key(file_key)

            if key_error:
                st.error(f"❌ {key_error}")
            else:
                st.markdown(
                    f'<div class="info-banner">'
                    f'<div class="banner-title">📄 Info File</div>'
                    f'<b>Nama:</b> {uploaded_file.name}<br>'
                    f'<b>Ukuran:</b> {len(file_data):,} bytes '
                    f'({len(file_data)/1024:.1f} KB)<br>'
                    f'<b>Tipe:</b> {uploaded_file.type or "unknown"}'
                    f'</div>',
                    unsafe_allow_html=True,
                )

                process_file_btn = st.button(
                    f"⚡ {'Enkripsi' if 'Enkripsi' in file_mode else 'Dekripsi'} File",
                    type="primary",
                    use_container_width=True,
                    key="file_process_btn",
                )

                if process_file_btn:
                    try:
                        cipher = HydraMatrixCipher(key_bytes)
                        start = time.perf_counter()

                        if "Enkripsi" in file_mode:
                            result_data = cipher.encrypt(file_data)
                            suffix = ".hydra"
                            elapsed = time.perf_counter() - start
                            download_name = uploaded_file.name + suffix
                        else:
                            result_data = cipher.decrypt(file_data)
                            elapsed = time.perf_counter() - start
                            if uploaded_file.name.endswith(".hydra"):
                                download_name = uploaded_file.name[:-6]
                            else:
                                download_name = "decrypted_" + uploaded_file.name

                        st.success(
                            f"✅ {'Enkripsi' if 'Enkripsi' in file_mode else 'Dekripsi'} "
                            f"selesai dalam {elapsed * 1000:.1f} ms"
                        )

                        col_fm1, col_fm2 = st.columns(2)
                        with col_fm1:
                            st.markdown(
                                create_metric_card(
                                    "Input",
                                    f"{len(file_data):,} B",
                                ),
                                unsafe_allow_html=True,
                            )
                        with col_fm2:
                            st.markdown(
                                create_metric_card(
                                    "Output",
                                    f"{len(result_data):,} B",
                                ),
                                unsafe_allow_html=True,
                            )

                        st.download_button(
                            label=f"⬇️ Download {download_name}",
                            data=result_data,
                            file_name=download_name,
                            use_container_width=True,
                        )

                    except Exception as e:
                        st.error(f"❌ Error: {str(e)}")


# ============================================================
# TAB 3: Visualisasi Proses
# ============================================================

with tab_visual:
    st.markdown("### 🔍 Visualisasi Proses Enkripsi")
    st.markdown(
        "> Lihat bagaimana setiap round mengubah state data "
        "melalui SubBytes, ShiftRows, MixColumns, dan AddRoundKey."
    )

    col_v1, col_v2 = st.columns([1, 2])

    with col_v1:
        vis_key = st.text_input(
            "🔑 Kunci",
            value="HydraMatrix!2026",
            max_chars=32,
            key="vis_key",
        )
        vis_plaintext = st.text_input(
            "📝 Plaintext (tepat 16 karakter)",
            value="Visualisasi!!!!",
            max_chars=16,
            key="vis_pt",
        )
        vis_btn = st.button(
            "🔍 Visualisasikan",
            type="primary",
            use_container_width=True,
            key="vis_btn",
        )

    with col_v2:
        if vis_btn:
            key_bytes, key_error = validate_key(vis_key)
            if key_error:
                st.error(f"❌ {key_error}")
            else:
                pt_bytes = vis_plaintext.encode("utf-8")
                if len(pt_bytes) < 16:
                    pt_bytes = pt_bytes.ljust(16, b"\x00")
                elif len(pt_bytes) > 16:
                    pt_bytes = pt_bytes[:16]

                try:
                    cipher = HydraMatrixCipher(key_bytes)
                    log = cipher.encrypt_block_verbose(pt_bytes)

                    st.markdown(
                        f'<div class="process-step">'
                        f'<div class="step-label">Input Plaintext</div>'
                        f'{log["input"]}'
                        f'</div>',
                        unsafe_allow_html=True,
                    )

                    st.markdown(
                        f'<div class="process-step">'
                        f'<div class="step-label">Initial Whitening (⊕ RK₀)</div>'
                        f'{log["initial_whitening"]}'
                        f'</div>',
                        unsafe_allow_html=True,
                    )

                    for round_data in log["rounds"]:
                        rn = round_data["round"]
                        with st.expander(f"🔄 Round {rn}", expanded=(rn <= 2)):
                            st.markdown(
                                f'<div class="process-step">'
                                f'<div class="step-label">SubBytes</div>'
                                f'{round_data["sub_bytes"]}'
                                f'</div>',
                                unsafe_allow_html=True,
                            )
                            st.markdown(
                                f'<div class="process-step">'
                                f'<div class="step-label">ShiftRows</div>'
                                f'{round_data["shift_rows"]}'
                                f'</div>',
                                unsafe_allow_html=True,
                            )
                            if "mix_columns" in round_data:
                                st.markdown(
                                    f'<div class="process-step">'
                                    f'<div class="step-label">MixColumns</div>'
                                    f'{round_data["mix_columns"]}'
                                    f'</div>',
                                    unsafe_allow_html=True,
                                )
                            st.markdown(
                                f'<div class="process-step">'
                                f'<div class="step-label">AddRoundKey (⊕ RK{rn})</div>'
                                f'{round_data["add_round_key"]}'
                                f'</div>',
                                unsafe_allow_html=True,
                            )

                    st.markdown(
                        f'<div class="result-box">'
                        f'<span class="label">🔐 Ciphertext Final</span>'
                        f'{log["output"]}'
                        f'</div>',
                        unsafe_allow_html=True,
                    )

                except Exception as e:
                    st.error(f"❌ Error: {str(e)}")


# ============================================================
# TAB 4: Analisis & Pengujian
# ============================================================

with tab_analysis:
    st.markdown("### 📊 Analisis & Pengujian")

    analysis_tab1, analysis_tab2 = st.tabs([
        "🌊 Avalanche Effect",
        "⚡ Performa",
    ])

    # ---- Avalanche Effect ----
    with analysis_tab1:
        st.markdown("""
        **Avalanche Effect** adalah sifat kriptografi dimana perubahan 1 bit
        pada input menyebabkan perubahan ~50% (64 dari 128 bit) pada output.
        """)

        if st.button("🚀 Jalankan Analisis Avalanche", type="primary",
                      key="avalanche_btn", use_container_width=True):
            with st.spinner("Menganalisis Avalanche Effect..."):
                pt_result = analyze_plaintext_avalanche()
                key_result = analyze_key_avalanche()

            # Metric cards
            col_a1, col_a2, col_a3, col_a4 = st.columns(4)
            with col_a1:
                st.markdown(
                    create_metric_card(
                        "PT Avalanche",
                        f"{pt_result['avg_percentage']:.1f}%",
                        f"avg {pt_result['average']:.1f} / {pt_result['total_bits']} bits",
                    ),
                    unsafe_allow_html=True,
                )
            with col_a2:
                st.markdown(
                    create_metric_card(
                        "Ideal",
                        "50.0%",
                        "64 / 128 bits",
                    ),
                    unsafe_allow_html=True,
                )
            with col_a3:
                st.markdown(
                    create_metric_card(
                        "Key Avalanche",
                        f"{key_result['avg_percentage']:.1f}%",
                        f"avg {key_result['average']:.1f} / {key_result['total_bits']} bits",
                    ),
                    unsafe_allow_html=True,
                )
            with col_a4:
                st.markdown(
                    create_metric_card(
                        "Min / Max (PT)",
                        f"{pt_result['min']} / {pt_result['max']}",
                        "bits changed",
                    ),
                    unsafe_allow_html=True,
                )

            # Charts
            col_chart1, col_chart2 = st.columns(2)

            with col_chart1:
                fig, ax = plt.subplots(figsize=(8, 4))
                fig.patch.set_facecolor("#0f172a")
                ax.set_facecolor("#1e1b4b")

                bit_positions = range(len(pt_result["bit_changes"]))
                bars = ax.bar(
                    bit_positions,
                    pt_result["bit_changes"],
                    color="#8b5cf6",
                    alpha=0.8,
                    width=1.0,
                )
                ax.axhline(
                    y=64, color="#f472b6", linestyle="--",
                    linewidth=2, label="Ideal (64 bits)",
                )
                ax.axhline(
                    y=pt_result["average"], color="#38bdf8",
                    linestyle="-", linewidth=2,
                    label=f"Rata-rata ({pt_result['average']:.1f})",
                )
                ax.set_xlabel("Bit Position (Plaintext)", color="#94a3b8", fontsize=10)
                ax.set_ylabel("Bit Changes (Ciphertext)", color="#94a3b8", fontsize=10)
                ax.set_title("Plaintext Avalanche Effect", color="#e2e8f0",
                             fontsize=13, fontweight="bold")
                ax.legend(facecolor="#1e1b4b", edgecolor="#8b5cf6",
                          labelcolor="#e2e8f0", fontsize=9)
                ax.tick_params(colors="#94a3b8")
                for spine in ax.spines.values():
                    spine.set_color("#4c1d95")

                st.pyplot(fig, use_container_width=True)
                plt.close(fig)

            with col_chart2:
                fig, ax = plt.subplots(figsize=(8, 4))
                fig.patch.set_facecolor("#0f172a")
                ax.set_facecolor("#1e1b4b")

                bit_positions = range(len(key_result["bit_changes"]))
                ax.bar(
                    bit_positions,
                    key_result["bit_changes"],
                    color="#f472b6",
                    alpha=0.8,
                    width=1.0,
                )
                ax.axhline(
                    y=64, color="#8b5cf6", linestyle="--",
                    linewidth=2, label="Ideal (64 bits)",
                )
                ax.axhline(
                    y=key_result["average"], color="#38bdf8",
                    linestyle="-", linewidth=2,
                    label=f"Rata-rata ({key_result['average']:.1f})",
                )
                ax.set_xlabel("Bit Position (Key)", color="#94a3b8", fontsize=10)
                ax.set_ylabel("Bit Changes (Ciphertext)", color="#94a3b8", fontsize=10)
                ax.set_title("Key Avalanche Effect", color="#e2e8f0",
                             fontsize=13, fontweight="bold")
                ax.legend(facecolor="#1e1b4b", edgecolor="#f472b6",
                          labelcolor="#e2e8f0", fontsize=9)
                ax.tick_params(colors="#94a3b8")
                for spine in ax.spines.values():
                    spine.set_color("#4c1d95")

                st.pyplot(fig, use_container_width=True)
                plt.close(fig)

            # Data tabel
            with st.expander("📋 Data Detail Avalanche"):
                detail_df = pd.DataFrame({
                    "Metrik": [
                        "Rata-rata Bit Berubah (Plaintext)",
                        "Persentase (Plaintext)",
                        "Min Bit Berubah (Plaintext)",
                        "Max Bit Berubah (Plaintext)",
                        "Rata-rata Bit Berubah (Key)",
                        "Persentase (Key)",
                        "Min Bit Berubah (Key)",
                        "Max Bit Berubah (Key)",
                        "Total Bit per Block",
                        "Target Ideal",
                    ],
                    "Nilai": [
                        f"{pt_result['average']:.2f}",
                        f"{pt_result['avg_percentage']:.2f}%",
                        str(pt_result["min"]),
                        str(pt_result["max"]),
                        f"{key_result['average']:.2f}",
                        f"{key_result['avg_percentage']:.2f}%",
                        str(key_result["min"]),
                        str(key_result["max"]),
                        "128",
                        "50% (64 bits)",
                    ],
                })
                st.dataframe(detail_df, use_container_width=True, hide_index=True)

    # ---- Performance ----
    with analysis_tab2:
        st.markdown("""
        **Benchmark Performa** mengukur waktu enkripsi/dekripsi dan throughput
        untuk berbagai ukuran data.
        """)

        perf_sizes_options = st.multiselect(
            "Pilih ukuran data:",
            ["16 B", "256 B", "1 KB", "10 KB", "100 KB"],
            default=["16 B", "256 B", "1 KB", "10 KB"],
            key="perf_sizes",
        )

        size_map = {
            "16 B": ("16 B (1 block)", 16),
            "256 B": ("256 B", 256),
            "1 KB": ("1 KB", 1024),
            "10 KB": ("10 KB", 10 * 1024),
            "100 KB": ("100 KB", 100 * 1024),
        }

        if st.button("🚀 Jalankan Benchmark", type="primary",
                      key="perf_btn", use_container_width=True):
            selected_sizes = [size_map[s] for s in perf_sizes_options if s in size_map]

            if not selected_sizes:
                st.warning("⚠️ Pilih minimal satu ukuran data!")
            else:
                with st.spinner("Menjalankan benchmark..."):
                    results = benchmark_encryption(data_sizes=selected_sizes)

                # Table
                df = pd.DataFrame(results)
                df_display = df.rename(columns={
                    "label": "Ukuran Data",
                    "encrypt_time_ms": "Enkripsi (ms)",
                    "decrypt_time_ms": "Dekripsi (ms)",
                    "encrypt_throughput_kbps": "Enkripsi (KB/s)",
                    "decrypt_throughput_kbps": "Dekripsi (KB/s)",
                })
                df_display = df_display.drop(columns=["size_bytes"], errors="ignore")
                st.dataframe(df_display, use_container_width=True, hide_index=True)

                # Charts
                col_p1, col_p2 = st.columns(2)

                with col_p1:
                    fig, ax = plt.subplots(figsize=(8, 4))
                    fig.patch.set_facecolor("#0f172a")
                    ax.set_facecolor("#1e1b4b")

                    labels = df["label"].tolist()
                    x = np.arange(len(labels))
                    width = 0.35

                    bars1 = ax.bar(
                        x - width / 2, df["encrypt_time_ms"],
                        width, label="Enkripsi", color="#8b5cf6", alpha=0.85,
                    )
                    bars2 = ax.bar(
                        x + width / 2, df["decrypt_time_ms"],
                        width, label="Dekripsi", color="#f472b6", alpha=0.85,
                    )

                    ax.set_xlabel("Ukuran Data", color="#94a3b8", fontsize=10)
                    ax.set_ylabel("Waktu (ms)", color="#94a3b8", fontsize=10)
                    ax.set_title("Waktu Enkripsi vs Dekripsi", color="#e2e8f0",
                                 fontsize=13, fontweight="bold")
                    ax.set_xticks(x)
                    ax.set_xticklabels(labels, fontsize=8, color="#94a3b8")
                    ax.legend(facecolor="#1e1b4b", edgecolor="#8b5cf6",
                              labelcolor="#e2e8f0", fontsize=9)
                    ax.tick_params(colors="#94a3b8")
                    for spine in ax.spines.values():
                        spine.set_color("#4c1d95")

                    st.pyplot(fig, use_container_width=True)
                    plt.close(fig)

                with col_p2:
                    fig, ax = plt.subplots(figsize=(8, 4))
                    fig.patch.set_facecolor("#0f172a")
                    ax.set_facecolor("#1e1b4b")

                    ax.bar(
                        x - width / 2, df["encrypt_throughput_kbps"],
                        width, label="Enkripsi", color="#8b5cf6", alpha=0.85,
                    )
                    ax.bar(
                        x + width / 2, df["decrypt_throughput_kbps"],
                        width, label="Dekripsi", color="#f472b6", alpha=0.85,
                    )

                    ax.set_xlabel("Ukuran Data", color="#94a3b8", fontsize=10)
                    ax.set_ylabel("Throughput (KB/s)", color="#94a3b8", fontsize=10)
                    ax.set_title("Throughput Enkripsi vs Dekripsi", color="#e2e8f0",
                                 fontsize=13, fontweight="bold")
                    ax.set_xticks(x)
                    ax.set_xticklabels(labels, fontsize=8, color="#94a3b8")
                    ax.legend(facecolor="#1e1b4b", edgecolor="#f472b6",
                              labelcolor="#e2e8f0", fontsize=9)
                    ax.tick_params(colors="#94a3b8")
                    for spine in ax.spines.values():
                        spine.set_color("#4c1d95")

                    st.pyplot(fig, use_container_width=True)
                    plt.close(fig)


# ============================================================
# Footer
# ============================================================

st.markdown("---")
st.markdown(
    '<p style="text-align:center; color:#64748b; font-size:0.82rem;">'
    '🐉 HydraMatrix Cipher v1.0 — Custom Cryptographic Algorithm '
    '— Built with Python & Streamlit'
    '</p>',
    unsafe_allow_html=True,
)
