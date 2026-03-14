"""
Key Schedule & S-Box Generation
=================================

Modul untuk menghasilkan:
1. Key-Dependent S-Box (substitusi dinamis berdasarkan kunci)
2. Round Keys melalui Bitwise Feedback Key Schedule

Keunikan HydraMatrix: S-Box dihasilkan secara unik untuk setiap kunci master,
berbeda dengan AES yang menggunakan S-Box statis.
"""

from typing import List


def generate_sbox(master_key: bytes) -> list:
    """
    Hasilkan S-Box 256-byte yang bergantung pada kunci master.

    Menggunakan Fisher-Yates shuffle dengan seed yang diturunkan dari kunci.
    Setiap kunci master menghasilkan S-Box yang unik, memberikan properti
    Confusion yang kuat.

    Args:
        master_key: Kunci master 16 bytes

    Returns:
        List 256 integer (0-255), merupakan permutasi bijektif
    """
    # Hitung seed dari master key
    seed = 0
    for j in range(len(master_key)):
        seed = (seed + master_key[j] * (j + 1)) & 0xFFFFFFFF

    # Fisher-Yates shuffle dengan Linear Congruential Generator
    sbox = list(range(256))
    for i in range(255, 0, -1):
        seed = (seed * 1103515245 + 12345) & 0xFFFFFFFF
        j = seed % (i + 1)
        sbox[i], sbox[j] = sbox[j], sbox[i]

    return sbox


def generate_inv_sbox(sbox: list) -> list:
    """
    Hasilkan inverse S-Box dari S-Box yang diberikan.

    Jika S-Box memetakan x → y, maka Inverse S-Box memetakan y → x.

    Args:
        sbox: S-Box 256-entry

    Returns:
        Inverse S-Box 256-entry
    """
    inv_sbox = [0] * 256
    for i in range(256):
        inv_sbox[sbox[i]] = i
    return inv_sbox


def _rotate_left_word(word: list, n: int) -> list:
    """
    Rotasi byte-level ke kiri pada sebuah word (list of bytes).

    Args:
        word: List of bytes
        n: Jumlah posisi rotasi

    Returns:
        Word yang sudah dirotasi
    """
    n = n % len(word)
    return word[n:] + word[:n]


def _sub_word(word: list, sbox: list) -> list:
    """
    Terapkan S-Box substitusi pada setiap byte dalam word.

    Args:
        word: List of bytes
        sbox: S-Box 256-entry

    Returns:
        Word yang sudah disubstitusi
    """
    return [sbox[b] for b in word]


def expand_key(master_key: bytes, sbox: list, num_rounds: int = 10) -> List[list]:
    """
    Ekspansi kunci master menjadi (num_rounds + 1) round keys.

    Menggunakan Bitwise Feedback Loop:
        RK₀ = master_key
        RKᵢ = RotateLeft(RKᵢ₋₁, i) ⊕ RCON[i] ⊕ SBox(RKᵢ₋₁[last_4_bytes])

    Round constant (RCON) diturunkan dari golden ratio:
        RCON[i] = (i * 0x9E3779B9) mod 2^32

    Args:
        master_key: Kunci master 16 bytes
        sbox: Key-dependent S-Box
        num_rounds: Jumlah round (default 10)

    Returns:
        List of (num_rounds+1) round keys, setiap key adalah list of 16 bytes
    """
    key_size = 16  # bytes
    round_keys = []

    # RK₀ = master key
    current_key = list(master_key[:key_size])
    round_keys.append(current_key[:])

    for i in range(1, num_rounds + 1):
        # Round constant dari golden ratio
        rcon_val = (i * 0x9E3779B9) & 0xFFFFFFFF
        rcon_bytes = [
            (rcon_val >> 24) & 0xFF,
            (rcon_val >> 16) & 0xFF,
            (rcon_val >> 8) & 0xFF,
            rcon_val & 0xFF,
        ]

        # Ambil 4 byte terakhir dari key sebelumnya, substitusi
        last_word = current_key[-4:]
        sub_last = _sub_word(last_word, sbox)

        # Rotasi key sebelumnya sebanyak i posisi (byte-level)
        rotated = _rotate_left_word(current_key, i)

        # XOR: rotated ⊕ RCON ⊕ sub_last (RCON dan sub_last di-cycle pada 16 bytes)
        new_key = []
        for j in range(key_size):
            byte_val = rotated[j]
            byte_val ^= rcon_bytes[j % 4]
            byte_val ^= sub_last[j % 4]
            new_key.append(byte_val & 0xFF)

        round_keys.append(new_key)
        current_key = new_key[:]

    return round_keys
