"""
Performance Benchmarks
=======================

Pengujian performa HydraMatrix Cipher:
- Waktu enkripsi/dekripsi berdasarkan ukuran data
- Throughput (KB/s)
- Hasil dalam format tabel
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hydra_cipher.core import HydraMatrixCipher


def benchmark_encryption(data_sizes: list = None,
                          key: bytes = b"HydraMatrix!2026",
                          iterations: int = 3) -> list:
    """
    Benchmark enkripsi untuk berbagai ukuran data.

    Args:
        data_sizes: List of (label, size_in_bytes) tuples
        key: Kunci enkripsi
        iterations: Jumlah iterasi untuk rata-rata

    Returns:
        List of dicts dengan: label, size_bytes, encrypt_time, decrypt_time,
        encrypt_throughput_kbps, decrypt_throughput_kbps
    """
    if data_sizes is None:
        data_sizes = [
            ("16 B (1 block)", 16),
            ("256 B", 256),
            ("1 KB", 1024),
            ("10 KB", 10 * 1024),
            ("100 KB", 100 * 1024),
            ("1 MB", 1024 * 1024),
        ]

    cipher = HydraMatrixCipher(key)
    results = []

    for label, size in data_sizes:
        # Generate random data
        plaintext = os.urandom(size)

        # Benchmark encryption
        enc_times = []
        ciphertext = None
        for _ in range(iterations):
            start = time.perf_counter()
            ciphertext = cipher.encrypt(plaintext)
            end = time.perf_counter()
            enc_times.append(end - start)

        # Benchmark decryption
        dec_times = []
        for _ in range(iterations):
            start = time.perf_counter()
            cipher.decrypt(ciphertext)
            end = time.perf_counter()
            dec_times.append(end - start)

        avg_enc = sum(enc_times) / len(enc_times)
        avg_dec = sum(dec_times) / len(dec_times)

        # Throughput dalam KB/s
        size_kb = size / 1024 if size >= 1024 else size / 1024
        enc_throughput = size_kb / avg_enc if avg_enc > 0 else 0
        dec_throughput = size_kb / avg_dec if avg_dec > 0 else 0

        results.append({
            "label": label,
            "size_bytes": size,
            "encrypt_time_ms": round(avg_enc * 1000, 3),
            "decrypt_time_ms": round(avg_dec * 1000, 3),
            "encrypt_throughput_kbps": round(enc_throughput, 2),
            "decrypt_throughput_kbps": round(dec_throughput, 2),
        })

    return results


def run_performance_benchmark() -> list:
    """Jalankan benchmark standar dan kembalikan hasilnya."""
    return benchmark_encryption()


# ============================================================
# Pytest tests
# ============================================================

def test_encryption_completes_within_timeout():
    """Enkripsi 10KB harus selesai dalam 30 detik."""
    cipher = HydraMatrixCipher(b"HydraMatrix!2026")
    data = os.urandom(10 * 1024)

    start = time.perf_counter()
    ct = cipher.encrypt(data)
    elapsed = time.perf_counter() - start

    assert elapsed < 30.0, f"Enkripsi 10KB terlalu lambat: {elapsed:.2f}s"
    assert cipher.decrypt(ct) == data


def test_decryption_completes_within_timeout():
    """Dekripsi 10KB harus selesai dalam 30 detik."""
    cipher = HydraMatrixCipher(b"HydraMatrix!2026")
    data = os.urandom(10 * 1024)
    ct = cipher.encrypt(data)

    start = time.perf_counter()
    pt = cipher.decrypt(ct)
    elapsed = time.perf_counter() - start

    assert elapsed < 30.0, f"Dekripsi 10KB terlalu lambat: {elapsed:.2f}s"
    assert pt == data


if __name__ == "__main__":
    print("=" * 70)
    print("HydraMatrix Cipher - Performance Benchmark")
    print("=" * 70)

    results = run_performance_benchmark()

    # Print table
    print(f"\n{'Data Size':<18} {'Encrypt (ms)':<15} {'Decrypt (ms)':<15} "
          f"{'Enc KB/s':<12} {'Dec KB/s':<12}")
    print("-" * 72)

    for r in results:
        print(f"{r['label']:<18} {r['encrypt_time_ms']:<15} "
              f"{r['decrypt_time_ms']:<15} "
              f"{r['encrypt_throughput_kbps']:<12} "
              f"{r['decrypt_throughput_kbps']:<12}")
