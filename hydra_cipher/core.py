"""
HydraMatrix Cipher - Core Implementation
==========================================

Implementasi utama algoritma HydraMatrix Cipher.

Kelas HydraMatrixCipher menyediakan:
- Enkripsi dan dekripsi block tunggal (16 bytes)
- Enkripsi dan dekripsi data multi-block dengan PKCS7 padding
- Operasi internal: SubBytes, ShiftRows, MixColumns, AddRoundKey (+ inverse)

Algoritma ini menggabungkan:
1. Key-Dependent S-Box → Confusion
2. ShiftRows + MixColumns → Diffusion
3. Bitwise Feedback Key Schedule → Key diversity
"""

from typing import List, Optional

from .gf_math import MUL2, MUL3, MUL9, MUL11, MUL13, MUL14
from .key_schedule import expand_key, generate_inv_sbox, generate_sbox
from .utils import (
    BLOCK_SIZE,
    bytes_to_matrix,
    matrix_to_bytes,
    pkcs7_pad,
    pkcs7_unpad,
)


class HydraMatrixCipher:
    """
    HydraMatrix Cipher - Algoritma Enkripsi Simetris Custom.

    Block size: 128-bit (16 bytes)
    Key size:   128-bit (16 bytes)
    Rounds:     10

    Contoh penggunaan:
        cipher = HydraMatrixCipher(key=b'kunci16bytes!!!')
        ciphertext = cipher.encrypt(b'Hello, World!!!')
        plaintext = cipher.decrypt(ciphertext)

    Attributes:
        num_rounds: Jumlah round enkripsi (default 10)
        sbox: Key-dependent Substitution Box
        inv_sbox: Inverse Substitution Box
        round_keys: List of round keys (num_rounds + 1)
    """

    def __init__(self, key: bytes, num_rounds: int = 10):
        """
        Inisialisasi cipher dengan kunci master.

        Args:
            key: Kunci master, harus tepat 16 bytes
            num_rounds: Jumlah round enkripsi (default 10)

        Raises:
            ValueError: Jika panjang kunci bukan 16 bytes
        """
        if len(key) != BLOCK_SIZE:
            raise ValueError(
                f"Panjang kunci harus {BLOCK_SIZE} bytes, "
                f"diterima {len(key)} bytes"
            )

        self.num_rounds = num_rounds
        self.key = key

        # Generate key-dependent S-Box
        self.sbox = generate_sbox(key)
        self.inv_sbox = generate_inv_sbox(self.sbox)

        # Key expansion
        self.round_keys = expand_key(key, self.sbox, num_rounds)

    # ================================================================
    # Operasi Inti Enkripsi
    # ================================================================

    def _sub_bytes(self, state: List[List[int]]) -> List[List[int]]:
        """
        Substitusi setiap byte dalam state menggunakan S-Box.

        Operasi non-linear yang memberikan properti Confusion.

        Args:
            state: Matriks 4×4

        Returns:
            State setelah substitusi
        """
        for i in range(4):
            for j in range(4):
                state[i][j] = self.sbox[state[i][j]]
        return state

    def _inv_sub_bytes(self, state: List[List[int]]) -> List[List[int]]:
        """Inverse SubBytes menggunakan inverse S-Box."""
        for i in range(4):
            for j in range(4):
                state[i][j] = self.inv_sbox[state[i][j]]
        return state

    def _shift_rows(self, state: List[List[int]], round_num: int) -> List[List[int]]:
        """
        Geser siklikal setiap baris state.

        Baris ke-i digeser ke kiri sebanyak (i + round_num) mod 4 posisi.
        Dynamic shift amount berdasarkan nomor round memberikan variasi
        pola difusi antar round.

        Args:
            state: Matriks 4×4
            round_num: Nomor round (1-10)

        Returns:
            State setelah pergeseran baris
        """
        for i in range(1, 4):  # Baris 0 tidak digeser
            shift = (i + round_num) % 4
            if shift == 0:
                shift = i  # Pastikan selalu ada pergeseran
            state[i] = state[i][shift:] + state[i][:shift]
        return state

    def _inv_shift_rows(
        self, state: List[List[int]], round_num: int
    ) -> List[List[int]]:
        """Inverse ShiftRows — geser ke kanan."""
        for i in range(1, 4):
            shift = (i + round_num) % 4
            if shift == 0:
                shift = i
            state[i] = state[i][-shift:] + state[i][:-shift]
        return state

    def _mix_columns(self, state: List[List[int]]) -> List[List[int]]:
        """
        Campurkan setiap kolom state menggunakan perkalian matriks di GF(2^8).

        Matriks:
            | 2  3  1  1 |
            | 1  2  3  1 |
            | 1  1  2  3 |
            | 3  1  1  2 |

        Operasi linear ini memberikan difusi optimal — setiap byte output
        bergantung pada semua 4 byte input dalam kolom.

        Args:
            state: Matriks 4×4

        Returns:
            State setelah pencampuran kolom
        """
        for col in range(4):
            s0 = state[0][col]
            s1 = state[1][col]
            s2 = state[2][col]
            s3 = state[3][col]

            state[0][col] = MUL2[s0] ^ MUL3[s1] ^ s2 ^ s3
            state[1][col] = s0 ^ MUL2[s1] ^ MUL3[s2] ^ s3
            state[2][col] = s0 ^ s1 ^ MUL2[s2] ^ MUL3[s3]
            state[3][col] = MUL3[s0] ^ s1 ^ s2 ^ MUL2[s3]

        return state

    def _inv_mix_columns(self, state: List[List[int]]) -> List[List[int]]:
        """
        Inverse MixColumns menggunakan matriks invers di GF(2^8).

        Matriks Invers:
            | 14  11  13   9 |
            |  9  14  11  13 |
            | 13   9  14  11 |
            | 11  13   9  14 |
        """
        for col in range(4):
            s0 = state[0][col]
            s1 = state[1][col]
            s2 = state[2][col]
            s3 = state[3][col]

            state[0][col] = MUL14[s0] ^ MUL11[s1] ^ MUL13[s2] ^ MUL9[s3]
            state[1][col] = MUL9[s0] ^ MUL14[s1] ^ MUL11[s2] ^ MUL13[s3]
            state[2][col] = MUL13[s0] ^ MUL9[s1] ^ MUL14[s2] ^ MUL11[s3]
            state[3][col] = MUL11[s0] ^ MUL13[s1] ^ MUL9[s2] ^ MUL14[s3]

        return state

    def _add_round_key(
        self, state: List[List[int]], round_key: list
    ) -> List[List[int]]:
        """
        XOR state dengan round key.

        XOR adalah operasinya sendiri yang merupakan inverse, sehingga
        fungsi yang sama digunakan untuk enkripsi dan dekripsi.

        Args:
            state: Matriks 4×4
            round_key: 16 bytes round key

        Returns:
            State setelah XOR dengan round key
        """
        key_matrix = []
        for row in range(4):
            key_matrix.append([round_key[row + 4 * col] for col in range(4)])

        for i in range(4):
            for j in range(4):
                state[i][j] ^= key_matrix[i][j]

        return state

    # ================================================================
    # Enkripsi / Dekripsi Block Tunggal
    # ================================================================

    def encrypt_block(self, block: bytes) -> bytes:
        """
        Enkripsi satu block 16-byte.

        Alur:
            1. Initial whitening: state = plaintext ⊕ RK₀
            2. Untuk round 1..10:
                a. SubBytes(state)
                b. ShiftRows(state, round)
                c. MixColumns(state)   [kecuali round terakhir]
                d. AddRoundKey(state, RKᵢ)
            3. Output: ciphertext = state

        Args:
            block: 16 bytes plaintext

        Returns:
            16 bytes ciphertext

        Raises:
            ValueError: Jika block bukan 16 bytes
        """
        if len(block) != BLOCK_SIZE:
            raise ValueError(f"Block harus {BLOCK_SIZE} bytes")

        # Konversi ke matriks 4×4
        state = bytes_to_matrix(block)

        # Initial whitening
        state = self._add_round_key(state, self.round_keys[0])

        # Round 1 sampai num_rounds
        for round_num in range(1, self.num_rounds + 1):
            state = self._sub_bytes(state)
            state = self._shift_rows(state, round_num)
            if round_num < self.num_rounds:
                state = self._mix_columns(state)
            state = self._add_round_key(state, self.round_keys[round_num])

        return matrix_to_bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        """
        Dekripsi satu block 16-byte.

        Inverse dari encrypt_block — semua operasi dibalik urutannya.

        Args:
            block: 16 bytes ciphertext

        Returns:
            16 bytes plaintext
        """
        if len(block) != BLOCK_SIZE:
            raise ValueError(f"Block harus {BLOCK_SIZE} bytes")

        state = bytes_to_matrix(block)

        # Inverse rounds: num_rounds..1
        for round_num in range(self.num_rounds, 0, -1):
            state = self._add_round_key(state, self.round_keys[round_num])
            if round_num < self.num_rounds:
                state = self._inv_mix_columns(state)
            state = self._inv_shift_rows(state, round_num)
            state = self._inv_sub_bytes(state)

        # Remove initial whitening
        state = self._add_round_key(state, self.round_keys[0])

        return matrix_to_bytes(state)

    # ================================================================
    # Enkripsi / Dekripsi Data (Multi-block dengan Padding)
    # ================================================================

    def encrypt(self, data: bytes) -> bytes:
        """
        Enkripsi data dengan panjang sembarang.

        Menggunakan PKCS7 padding dan mode ECB
        (Electronic Codebook — setiap block dienkripsi secara independen).

        Args:
            data: Plaintext bytes

        Returns:
            Ciphertext bytes (selalu kelipatan 16)
        """
        padded = pkcs7_pad(data)
        ciphertext = b""

        for i in range(0, len(padded), BLOCK_SIZE):
            block = padded[i : i + BLOCK_SIZE]
            ciphertext += self.encrypt_block(block)

        return ciphertext

    def decrypt(self, data: bytes) -> bytes:
        """
        Dekripsi data terenkripsi.

        Args:
            data: Ciphertext bytes (harus kelipatan 16)

        Returns:
            Plaintext bytes (padding dihapus)

        Raises:
            ValueError: Jika panjang data bukan kelipatan 16
        """
        if len(data) % BLOCK_SIZE != 0:
            raise ValueError(
                f"Ciphertext harus kelipatan {BLOCK_SIZE} bytes, "
                f"diterima {len(data)} bytes"
            )

        plaintext = b""
        for i in range(0, len(data), BLOCK_SIZE):
            block = data[i : i + BLOCK_SIZE]
            plaintext += self.decrypt_block(block)

        return pkcs7_unpad(plaintext)

    # ================================================================
    # Visualisasi Proses (untuk UI)
    # ================================================================

    def encrypt_block_verbose(self, block: bytes) -> dict:
        """
        Enkripsi satu block dengan log detail setiap langkah.

        Mengembalikan dictionary berisi state setelah setiap operasi,
        berguna untuk visualisasi proses di UI.

        Args:
            block: 16 bytes plaintext

        Returns:
            Dict dengan key: 'input', 'initial_whitening', 'rounds'
            Setiap round berisi: 'sub_bytes', 'shift_rows',
            'mix_columns' (jika ada), 'add_round_key'
        """
        if len(block) != BLOCK_SIZE:
            raise ValueError(f"Block harus {BLOCK_SIZE} bytes")

        log = {
            "input": block.hex(),
            "rounds": [],
        }

        state = bytes_to_matrix(block)
        state = self._add_round_key(state, self.round_keys[0])
        log["initial_whitening"] = matrix_to_bytes(state).hex()

        for round_num in range(1, self.num_rounds + 1):
            round_log = {"round": round_num}

            state = self._sub_bytes(state)
            round_log["sub_bytes"] = matrix_to_bytes(state).hex()

            state = self._shift_rows(state, round_num)
            round_log["shift_rows"] = matrix_to_bytes(state).hex()

            if round_num < self.num_rounds:
                state = self._mix_columns(state)
                round_log["mix_columns"] = matrix_to_bytes(state).hex()

            state = self._add_round_key(state, self.round_keys[round_num])
            round_log["add_round_key"] = matrix_to_bytes(state).hex()

            log["rounds"].append(round_log)

        log["output"] = matrix_to_bytes(state).hex()
        return log
