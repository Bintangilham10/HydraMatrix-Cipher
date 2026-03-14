"""
Avalanche Effect Analysis
==========================

Analisis Avalanche Effect untuk HydraMatrix Cipher.

Avalanche Effect adalah properti kriptografi dimana perubahan kecil
pada input (1 bit) menyebabkan perubahan besar (~50%) pada output.

Test ini mengukur:
1. Plaintext Avalanche: flip 1 bit pada plaintext, ukur perubahan ciphertext
2. Key Avalanche: flip 1 bit pada key, ukur perubahan ciphertext
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hydra_cipher.core import HydraMatrixCipher
from hydra_cipher.utils import hamming_distance


def flip_bit(data: bytes, bit_position: int) -> bytes:
    """
    Flip satu bit pada posisi tertentu dalam data.

    Args:
        data: Bytes data asli
        bit_position: Posisi bit (0-indexed dari MSB byte pertama)

    Returns:
        Data baru dengan satu bit yang di-flip
    """
    byte_pos = bit_position // 8
    bit_pos = 7 - (bit_position % 8)
    data_list = list(data)
    data_list[byte_pos] ^= (1 << bit_pos)
    return bytes(data_list)


def analyze_plaintext_avalanche(key: bytes = b"HydraMatrix!2026",
                                 plaintext: bytes = b"AvalancheTest!!!"
                                 ) -> dict:
    """
    Analisis Avalanche Effect terhadap perubahan plaintext.

    Untuk setiap bit dalam plaintext 16-byte (128 bit):
    1. Flip bit tersebut
    2. Enkripsi plaintext asli dan plaintext yang dimodifikasi
    3. Hitung Hamming distance antara kedua ciphertext

    Args:
        key: Kunci enkripsi (16 bytes)
        plaintext: Plaintext dasar (16 bytes)

    Returns:
        Dict berisi: bit_changes (list), average, min, max, percentage
    """
    cipher = HydraMatrixCipher(key)
    original_ct = cipher.encrypt_block(plaintext)

    total_bits = len(plaintext) * 8  # 128 bits
    bit_changes = []

    for bit_pos in range(total_bits):
        modified_pt = flip_bit(plaintext, bit_pos)
        modified_ct = cipher.encrypt_block(modified_pt)
        hd = hamming_distance(original_ct, modified_ct)
        bit_changes.append(hd)

    avg_change = sum(bit_changes) / len(bit_changes)
    return {
        "type": "plaintext",
        "bit_changes": bit_changes,
        "average": avg_change,
        "min": min(bit_changes),
        "max": max(bit_changes),
        "total_bits": total_bits,
        "avg_percentage": (avg_change / total_bits) * 100,
        "ideal_percentage": 50.0,
    }


def analyze_key_avalanche(key: bytes = b"HydraMatrix!2026",
                           plaintext: bytes = b"AvalancheTest!!!"
                           ) -> dict:
    """
    Analisis Avalanche Effect terhadap perubahan key.

    Untuk setiap bit dalam key 16-byte (128 bit):
    1. Flip bit tersebut pada key
    2. Enkripsi plaintext yang sama dengan key asli dan key yang dimodifikasi
    3. Hitung Hamming distance antara kedua ciphertext

    Args:
        key: Kunci asli (16 bytes)
        plaintext: Plaintext tetap (16 bytes)

    Returns:
        Dict berisi: bit_changes (list), average, min, max, percentage
    """
    original_cipher = HydraMatrixCipher(key)
    original_ct = original_cipher.encrypt_block(plaintext)

    total_bits = len(key) * 8  # 128 bits
    bit_changes = []

    for bit_pos in range(total_bits):
        modified_key = flip_bit(key, bit_pos)
        modified_cipher = HydraMatrixCipher(modified_key)
        modified_ct = modified_cipher.encrypt_block(plaintext)
        hd = hamming_distance(original_ct, modified_ct)
        bit_changes.append(hd)

    avg_change = sum(bit_changes) / len(bit_changes)
    return {
        "type": "key",
        "bit_changes": bit_changes,
        "average": avg_change,
        "min": min(bit_changes),
        "max": max(bit_changes),
        "total_bits": total_bits,
        "avg_percentage": (avg_change / total_bits) * 100,
        "ideal_percentage": 50.0,
    }


def run_full_avalanche_analysis() -> dict:
    """
    Jalankan analisis avalanche lengkap (plaintext + key).

    Returns:
        Dict berisi 'plaintext_avalanche' dan 'key_avalanche'
    """
    start_time = time.time()

    pt_result = analyze_plaintext_avalanche()
    key_result = analyze_key_avalanche()

    elapsed = time.time() - start_time

    return {
        "plaintext_avalanche": pt_result,
        "key_avalanche": key_result,
        "analysis_time_seconds": round(elapsed, 3),
    }


# ============================================================
# Pytest tests
# ============================================================

def test_plaintext_avalanche_above_threshold():
    """Rata-rata perubahan bit harus >= 35% (threshold minimal)."""
    result = analyze_plaintext_avalanche()
    assert result["avg_percentage"] >= 35.0, (
        f"Avalanche plaintext terlalu rendah: {result['avg_percentage']:.1f}%"
    )


def test_key_avalanche_above_threshold():
    """Rata-rata perubahan bit dari key harus >= 35%."""
    result = analyze_key_avalanche()
    assert result["avg_percentage"] >= 35.0, (
        f"Avalanche key terlalu rendah: {result['avg_percentage']:.1f}%"
    )


def test_no_zero_change():
    """Tidak ada bit flip yang menghasilkan 0 perubahan pada ciphertext."""
    pt_result = analyze_plaintext_avalanche()
    assert all(c > 0 for c in pt_result["bit_changes"]), (
        "Ada bit flip plaintext yang tidak menyebabkan perubahan pada ciphertext!"
    )

    key_result = analyze_key_avalanche()
    assert all(c > 0 for c in key_result["bit_changes"]), (
        "Ada bit flip key yang tidak menyebabkan perubahan pada ciphertext!"
    )


if __name__ == "__main__":
    print("=" * 60)
    print("HydraMatrix Cipher - Avalanche Effect Analysis")
    print("=" * 60)

    results = run_full_avalanche_analysis()

    for label, data in [("Plaintext", results["plaintext_avalanche"]),
                        ("Key", results["key_avalanche"])]:
        print(f"\n{label} Avalanche:")
        print(f"  Rata-rata perubahan bit: {data['average']:.1f} / {data['total_bits']}")
        print(f"  Persentase rata-rata:    {data['avg_percentage']:.1f}%")
        print(f"  Minimum:                 {data['min']} bit")
        print(f"  Maksimum:                {data['max']} bit")
        print(f"  Ideal:                   {data['ideal_percentage']}%")

    print(f"\nWaktu analisis: {results['analysis_time_seconds']}s")
