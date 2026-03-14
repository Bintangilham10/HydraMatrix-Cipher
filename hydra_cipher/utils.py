"""
Utility Functions
==================

Fungsi utilitas untuk HydraMatrix Cipher:
- PKCS7 padding/unpadding
- Konversi bytes ↔ 4×4 matrix
- Rotasi bitwise
"""

from typing import List

BLOCK_SIZE = 16  # bytes


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    Terapkan PKCS7 padding pada data.

    Menambahkan n byte bernilai n di akhir data, dimana n adalah
    jumlah byte yang diperlukan agar panjang data menjadi kelipatan block_size.

    Args:
        data: Data yang akan di-pad
        block_size: Ukuran blok (default 16)

    Returns:
        Data yang sudah di-pad
    """
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Hapus PKCS7 padding dari data.

    Args:
        data: Data yang memiliki PKCS7 padding

    Returns:
        Data tanpa padding

    Raises:
        ValueError: Jika padding tidak valid
    """
    if not data:
        raise ValueError("Data kosong, tidak dapat menghapus padding")

    pad_len = data[-1]

    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError(f"Nilai padding tidak valid: {pad_len}")

    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding PKCS7 tidak valid")

    return data[:-pad_len]


def bytes_to_matrix(block: bytes) -> List[List[int]]:
    """
    Konversi 16-byte block menjadi matriks 4×4 (column-major order).

    Layout matriks (sesuai konvensi kriptografi):
        [b0  b4  b8   b12]
        [b1  b5  b9   b13]
        [b2  b6  b10  b14]
        [b3  b7  b11  b15]

    Args:
        block: 16 bytes

    Returns:
        Matriks 4×4 (list of 4 rows, each row has 4 elements)
    """
    matrix = []
    for row in range(4):
        matrix.append([block[row + 4 * col] for col in range(4)])
    return matrix


def matrix_to_bytes(matrix: List[List[int]]) -> bytes:
    """
    Konversi matriks 4×4 kembali menjadi 16-byte block (column-major order).

    Args:
        matrix: Matriks 4×4

    Returns:
        16 bytes
    """
    result = []
    for col in range(4):
        for row in range(4):
            result.append(matrix[row][col])
    return bytes(result)


def rotate_left_32(value: int, n: int) -> int:
    """
    Rotasi kiri 32-bit.

    Args:
        value: Nilai 32-bit
        n: Jumlah bit rotasi

    Returns:
        Nilai setelah rotasi
    """
    n = n % 32
    return ((value << n) | (value >> (32 - n))) & 0xFFFFFFFF


def hex_format(data: bytes) -> str:
    """
    Format bytes sebagai string hexadecimal yang mudah dibaca.

    Args:
        data: Bytes data

    Returns:
        String hex dengan spasi antar byte
    """
    return " ".join(f"{b:02x}" for b in data)


def hamming_distance(a: bytes, b: bytes) -> int:
    """
    Hitung Hamming distance (jumlah bit yang berbeda) antara dua byte sequences.

    Args:
        a: Byte sequence pertama
        b: Byte sequence kedua

    Returns:
        Jumlah bit yang berbeda
    """
    if len(a) != len(b):
        raise ValueError("Panjang kedua byte sequence harus sama")

    distance = 0
    for x, y in zip(a, b):
        xor = x ^ y
        # Hitung jumlah bit 1 dalam xor (popcount)
        distance += bin(xor).count("1")
    return distance
