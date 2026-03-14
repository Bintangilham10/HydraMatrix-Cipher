"""
Galois Field GF(2^8) Arithmetic
================================

Operasi aritmatika pada Galois Field GF(2^8) dengan irreducible polynomial:
    x^8 + x^4 + x^3 + x + 1  (0x11B)

Digunakan untuk operasi MixColumns dalam HydraMatrix Cipher.
"""

# Irreducible polynomial untuk GF(2^8): x^8 + x^4 + x^3 + x + 1
IRREDUCIBLE_POLY = 0x11B


def gf_multiply(a: int, b: int) -> int:
    """
    Perkalian dua elemen dalam GF(2^8).

    Menggunakan metode 'peasant multiplication' (shift-and-add)
    dengan reduksi modulo irreducible polynomial.

    Args:
        a: Elemen pertama (0-255)
        b: Elemen kedua (0-255)

    Returns:
        Hasil perkalian dalam GF(2^8)
    """
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        # Shift a ke kiri, reduksi jika overflow
        high_bit = a & 0x80
        a = (a << 1) & 0xFF
        if high_bit:
            a ^= IRREDUCIBLE_POLY & 0xFF  # Reduksi modulo polynomial
        b >>= 1
    return result


def gf_inverse(a: int) -> int:
    """
    Invers perkalian dalam GF(2^8).

    Menggunakan extended Euclidean algorithm untuk polynomial.
    Untuk a=0, mengembalikan 0 (konvensi kriptografi).

    Args:
        a: Elemen (0-255)

    Returns:
        Invers perkalian, atau 0 jika a=0
    """
    if a == 0:
        return 0
    # Menggunakan Fermat's little theorem: a^(-1) = a^(2^8 - 2) dalam GF(2^8)
    # 2^8 - 2 = 254
    result = a
    for _ in range(6):  # Menghitung a^254 melalui repeated squaring
        result = gf_multiply(result, result)
        result = gf_multiply(result, a)
    result = gf_multiply(result, result)
    return result


# ============================================================
# Precomputed Multiplication Tables
# ============================================================
# Tabel perkalian untuk konstanta yang digunakan dalam MixColumns
# dan InvMixColumns untuk performa optimal.

def _build_mul_table(constant: int) -> list:
    """Bangun tabel perkalian 256-entry untuk sebuah konstanta."""
    return [gf_multiply(i, constant) for i in range(256)]


# MixColumns constants
MUL2 = _build_mul_table(2)
MUL3 = _build_mul_table(3)

# InvMixColumns constants
MUL9 = _build_mul_table(9)
MUL11 = _build_mul_table(11)
MUL13 = _build_mul_table(13)
MUL14 = _build_mul_table(14)
