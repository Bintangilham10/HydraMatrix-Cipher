"""
HydraMatrix Cipher - Custom Symmetric Block Cipher
===================================================

Algoritma enkripsi simetris custom yang menggabungkan:
- Dynamic S-Box (key-dependent substitution)
- Matrix Transposition (ShiftRows + MixColumns over GF(2^8))
- Bitwise Feedback Key Schedule

Block size: 128-bit | Key size: 128-bit | Rounds: 10
"""

from .core import HydraMatrixCipher

__all__ = ["HydraMatrixCipher"]
__version__ = "1.0.0"
