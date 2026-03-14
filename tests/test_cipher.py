"""
Unit Tests untuk HydraMatrix Cipher
=====================================

Pengujian komprehensif mencakup:
- Roundtrip encrypt/decrypt
- Padding correctness
- S-Box bijectivity
- Key schedule distinctness
- Edge cases
"""

import pytest
import sys
import os

# Tambahkan parent directory ke path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hydra_cipher.core import HydraMatrixCipher
from hydra_cipher.key_schedule import generate_sbox, generate_inv_sbox, expand_key
from hydra_cipher.utils import pkcs7_pad, pkcs7_unpad, bytes_to_matrix, matrix_to_bytes
from hydra_cipher.gf_math import gf_multiply, gf_inverse


# ============================================================
# Test Key & Fixtures
# ============================================================

TEST_KEY = b"HydraMatrix!2026"  # 16 bytes


@pytest.fixture
def cipher():
    """Cipher instance dengan kunci test."""
    return HydraMatrixCipher(TEST_KEY)


# ============================================================
# Test GF(2^8) Arithmetic
# ============================================================

class TestGFMath:
    """Test operasi Galois Field."""

    def test_gf_multiply_identity(self):
        """Perkalian dengan 1 menghasilkan nilai yang sama."""
        for i in range(256):
            assert gf_multiply(i, 1) == i

    def test_gf_multiply_zero(self):
        """Perkalian dengan 0 menghasilkan 0."""
        for i in range(256):
            assert gf_multiply(i, 0) == 0

    def test_gf_multiply_commutative(self):
        """Perkalian bersifat komutatif."""
        for a in range(0, 256, 17):  # Sample
            for b in range(0, 256, 19):
                assert gf_multiply(a, b) == gf_multiply(b, a)

    def test_gf_inverse_correctness(self):
        """a * a^(-1) = 1 untuk semua a != 0."""
        for a in range(1, 256):
            inv = gf_inverse(a)
            assert gf_multiply(a, inv) == 1, f"Inverse gagal untuk {a}"

    def test_gf_inverse_zero(self):
        """Inverse dari 0 adalah 0 (konvensi)."""
        assert gf_inverse(0) == 0


# ============================================================
# Test S-Box
# ============================================================

class TestSBox:
    """Test S-Box generation."""

    def test_sbox_is_permutation(self):
        """S-Box harus merupakan permutasi lengkap 0-255."""
        sbox = generate_sbox(TEST_KEY)
        assert sorted(sbox) == list(range(256))

    def test_sbox_bijective(self):
        """S-Box harus bijektif — semua 256 nilai muncul tepat sekali."""
        sbox = generate_sbox(TEST_KEY)
        assert len(set(sbox)) == 256

    def test_inverse_sbox_correctness(self):
        """InvSBox(SBox(x)) = x untuk semua x."""
        sbox = generate_sbox(TEST_KEY)
        inv_sbox = generate_inv_sbox(sbox)
        for x in range(256):
            assert inv_sbox[sbox[x]] == x

    def test_different_keys_produce_different_sboxes(self):
        """Kunci berbeda menghasilkan S-Box berbeda."""
        sbox1 = generate_sbox(b"KeyNumber1Here!!")
        sbox2 = generate_sbox(b"KeyNumber2Here!!")
        assert sbox1 != sbox2


# ============================================================
# Test Key Schedule
# ============================================================

class TestKeySchedule:
    """Test key expansion."""

    def test_round_keys_count(self):
        """Harus menghasilkan 11 round keys (untuk 10 round)."""
        sbox = generate_sbox(TEST_KEY)
        rks = expand_key(TEST_KEY, sbox, num_rounds=10)
        assert len(rks) == 11

    def test_round_keys_length(self):
        """Setiap round key harus 16 bytes."""
        sbox = generate_sbox(TEST_KEY)
        rks = expand_key(TEST_KEY, sbox, num_rounds=10)
        for rk in rks:
            assert len(rk) == 16

    def test_first_round_key_is_master_key(self):
        """Round key pertama harus sama dengan master key."""
        sbox = generate_sbox(TEST_KEY)
        rks = expand_key(TEST_KEY, sbox, num_rounds=10)
        assert rks[0] == list(TEST_KEY)

    def test_round_keys_are_distinct(self):
        """Semua round keys harus berbeda satu sama lain."""
        sbox = generate_sbox(TEST_KEY)
        rks = expand_key(TEST_KEY, sbox, num_rounds=10)
        # Konversi ke tuple untuk set comparison
        rk_tuples = [tuple(rk) for rk in rks]
        assert len(set(rk_tuples)) == 11


# ============================================================
# Test Padding
# ============================================================

class TestPadding:
    """Test PKCS7 padding."""

    def test_pad_exact_block(self):
        """Data tepat 16 bytes mendapat 16 bytes padding tambahan."""
        data = b"A" * 16
        padded = pkcs7_pad(data)
        assert len(padded) == 32
        assert padded[16:] == bytes([16] * 16)

    def test_pad_unpad_roundtrip(self):
        """Pad lalu unpad mengembalikan data asli."""
        for length in [1, 5, 15, 16, 17, 31, 32, 100]:
            data = bytes(range(length % 256)) * (length // 256 + 1)
            data = data[:length]
            assert pkcs7_unpad(pkcs7_pad(data)) == data

    def test_unpad_invalid_raises(self):
        """Unpad data invalid harus raise ValueError."""
        with pytest.raises(ValueError):
            pkcs7_unpad(b"")

    def test_unpad_bad_padding_raises(self):
        """Unpad dengan padding value salah harus raise ValueError."""
        with pytest.raises(ValueError):
            pkcs7_unpad(b"A" * 16)  # Last byte is 0x41, invalid


# ============================================================
# Test Matrix Conversion
# ============================================================

class TestMatrixConversion:
    """Test bytes ↔ matrix conversion."""

    def test_roundtrip(self):
        """bytes → matrix → bytes harus identik."""
        data = bytes(range(16))
        matrix = bytes_to_matrix(data)
        assert matrix_to_bytes(matrix) == data

    def test_matrix_shape(self):
        """Matrix harus 4×4."""
        matrix = bytes_to_matrix(bytes(16))
        assert len(matrix) == 4
        assert all(len(row) == 4 for row in matrix)


# ============================================================
# Test Encryption / Decryption
# ============================================================

class TestEncryptDecrypt:
    """Test enkripsi dan dekripsi."""

    def test_single_block_roundtrip(self, cipher):
        """Encrypt lalu decrypt satu block menghasilkan plaintext asli."""
        plaintext = b"Hello, HydraM!.."  # 16 bytes
        ciphertext = cipher.encrypt_block(plaintext)
        decrypted = cipher.decrypt_block(ciphertext)
        assert decrypted == plaintext

    def test_ciphertext_differs_from_plaintext(self, cipher):
        """Ciphertext harus berbeda dari plaintext."""
        plaintext = b"Hello, HydraM!.."
        ciphertext = cipher.encrypt_block(plaintext)
        assert ciphertext != plaintext

    def test_multi_block_roundtrip(self, cipher):
        """Encrypt/decrypt data multi-block."""
        plaintext = b"Ini adalah pesan rahasia yang panjangnya lebih dari satu block!"
        ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_empty_string(self, cipher):
        """Encrypt/decrypt string kosong."""
        plaintext = b""
        ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_single_byte(self, cipher):
        """Encrypt/decrypt satu byte."""
        plaintext = b"X"
        ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_exact_block_size(self, cipher):
        """Encrypt/decrypt data tepat 16 bytes."""
        plaintext = b"ExactlyOneBlock!"  # 16 bytes
        ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_exact_two_blocks(self, cipher):
        """Encrypt/decrypt data tepat 32 bytes."""
        plaintext = b"A" * 32
        ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_different_keys_produce_different_ciphertexts(self):
        """Kunci berbeda menghasilkan ciphertext berbeda."""
        plaintext = b"Same plaintext!!"  # 16 bytes
        cipher1 = HydraMatrixCipher(b"FirstKeyHere!!!!")
        cipher2 = HydraMatrixCipher(b"SecondKeyHere!!!")
        ct1 = cipher1.encrypt_block(plaintext)
        ct2 = cipher2.encrypt_block(plaintext)
        assert ct1 != ct2

    def test_invalid_key_length_raises(self):
        """Kunci dengan panjang != 16 harus raise ValueError."""
        with pytest.raises(ValueError):
            HydraMatrixCipher(b"short")
        with pytest.raises(ValueError):
            HydraMatrixCipher(b"this key is way too long for the cipher!")

    def test_invalid_block_size_raises(self, cipher):
        """Block bukan 16 bytes harus raise ValueError."""
        with pytest.raises(ValueError):
            cipher.encrypt_block(b"short")

    def test_deterministic_encryption(self, cipher):
        """Enkripsi plaintext yang sama dengan key yang sama = hasil sama."""
        plaintext = b"Test determinism"
        ct1 = cipher.encrypt_block(plaintext)
        ct2 = cipher.encrypt_block(plaintext)
        assert ct1 == ct2

    def test_large_data(self, cipher):
        """Encrypt/decrypt data besar (10KB)."""
        plaintext = os.urandom(10 * 1024)
        ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_verbose_encryption(self, cipher):
        """Verbose encryption menghasilkan log yang valid."""
        plaintext = b"Verbose Test!!!!"  # 16 bytes
        log = cipher.encrypt_block_verbose(plaintext)

        assert "input" in log
        assert "initial_whitening" in log
        assert "rounds" in log
        assert len(log["rounds"]) == 10
        assert "output" in log

        # Output harus sama dengan enkripsi normal
        normal_ct = cipher.encrypt_block(plaintext)
        assert log["output"] == normal_ct.hex()


# ============================================================
# Entry point untuk menjalankan langsung
# ============================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
