"""
Hill Cipher Implementation

The Hill Cipher is a polygraphic substitution cipher that encrypts text in blocks
using matrix multiplication in modular arithmetic.

Encryption:
    C = (K * P) mod 26

Decryption:
    P = (K^-1 * C) mod 26

Where:
- K is the encryption key matrix
- P is the plaintext block vector
- C is the ciphertext block vector
- K must be invertible modulo 26
"""

import math
from typing import List, Sequence


class HillCipher:
    """Hill Cipher encryption and decryption using a 2x2 key matrix."""

    ALPHABET_SIZE = 26
    ASCII_A = ord("A")
    BLOCK_SIZE = 2

    def __init__(self, key_matrix: Sequence[Sequence[int]]):
        """
        Initialize the Hill Cipher with a 2x2 key matrix.

        Args:
            key_matrix: A 2x2 matrix used as the encryption key.

        Raises:
            TypeError: If the matrix contains non-integer values.
            ValueError: If the matrix is not 2x2 or is not invertible mod 26.
        """

        self.key_matrix = self._validate_and_normalize_matrix(key_matrix)

        determinant = self._matrix_determinant(self.key_matrix)
        determinant_mod = determinant % self.ALPHABET_SIZE

        if math.gcd(determinant_mod, self.ALPHABET_SIZE) != 1:
            raise ValueError(
                f"Invalid key matrix: determinant is {determinant}, "
                f"and gcd({determinant_mod}, 26) is not 1. "
                "The matrix must be invertible modulo 26."
            )

        self.inverse_matrix = self._matrix_inverse(self.key_matrix)

    @classmethod
    def _validate_and_normalize_matrix(
        cls,
        matrix: Sequence[Sequence[int]]
    ) -> List[List[int]]:
        """
        Validate that the key matrix is 2x2 and contains only integers.
        Values are normalized using modulo 26.
        """

        if len(matrix) != 2:
            raise ValueError("Key matrix must have exactly 2 rows.")

        normalized_matrix = []

        for row in matrix:
            if len(row) != 2:
                raise ValueError("Each row in the key matrix must have exactly 2 values.")

            normalized_row = []

            for value in row:
                if not isinstance(value, int):
                    raise TypeError("All key matrix values must be integers.")

                normalized_row.append(value % cls.ALPHABET_SIZE)

            normalized_matrix.append(normalized_row)

        return normalized_matrix

    @staticmethod
    def _matrix_determinant(matrix: List[List[int]]) -> int:
        """
        Calculate the determinant of a 2x2 matrix.

        Formula:
            det = ad - bc
        """

        a, b = matrix[0]
        c, d = matrix[1]

        return (a * d) - (b * c)

    @staticmethod
    def _mod_inverse(a: int, m: int) -> int:
        """
        Calculate the modular multiplicative inverse of a modulo m
        using the Extended Euclidean Algorithm.
        """

        def extended_gcd(x: int, y: int):
            if x == 0:
                return y, 0, 1

            gcd_value, x1, y1 = extended_gcd(y % x, x)
            new_x = y1 - (y // x) * x1
            new_y = x1

            return gcd_value, new_x, new_y

        gcd_value, inverse, _ = extended_gcd(a % m, m)

        if gcd_value != 1:
            raise ValueError(f"No modular inverse exists for {a} modulo {m}.")

        return inverse % m

    def _matrix_inverse(self, matrix: List[List[int]]) -> List[List[int]]:
        """
        Calculate the inverse of a 2x2 matrix modulo 26.

        For matrix:
            [[a, b],
             [c, d]]

        The inverse is:
            determinant_inverse * [[d, -b],
                                   [-c, a]] mod 26
        """

        determinant = self._matrix_determinant(matrix)
        determinant_inverse = self._mod_inverse(
            determinant,
            self.ALPHABET_SIZE
        )

        a, b = matrix[0]
        c, d = matrix[1]

        inverse_matrix = [
            [
                (determinant_inverse * d) % self.ALPHABET_SIZE,
                (-determinant_inverse * b) % self.ALPHABET_SIZE
            ],
            [
                (-determinant_inverse * c) % self.ALPHABET_SIZE,
                (determinant_inverse * a) % self.ALPHABET_SIZE
            ]
        ]

        return inverse_matrix

    @classmethod
    def _matrix_multiply(
        cls,
        matrix: List[List[int]],
        vector: List[int]
    ) -> List[int]:
        """
        Multiply a 2x2 matrix by a 2x1 vector using modulo 26.
        """

        return [
            (matrix[0][0] * vector[0] + matrix[0][1] * vector[1]) % cls.ALPHABET_SIZE,
            (matrix[1][0] * vector[0] + matrix[1][1] * vector[1]) % cls.ALPHABET_SIZE
        ]

    @staticmethod
    def _preprocess_text(text: str) -> str:
        """
        Convert text to uppercase and keep only English letters A-Z.
        """

        if not isinstance(text, str):
            raise TypeError("Text must be a string.")

        return "".join(
            char.upper()
            for char in text
            if "A" <= char.upper() <= "Z"
        )

    @classmethod
    def _pad_text(cls, text: str) -> str:
        """
        Pad text with X if its length is not divisible by the block size.
        """

        remainder = len(text) % cls.BLOCK_SIZE

        if remainder != 0:
            padding_needed = cls.BLOCK_SIZE - remainder
            text += "X" * padding_needed

        return text

    @classmethod
    def _text_to_numbers(cls, text_block: str) -> List[int]:
        """
        Convert a block of letters into numbers.
        Example:
            A = 0, B = 1, ..., Z = 25
        """

        return [
            ord(char) - cls.ASCII_A
            for char in text_block
        ]

    @classmethod
    def _numbers_to_text(cls, numbers: List[int]) -> str:
        """
        Convert numbers back into letters.
        """

        return "".join(
            chr(number + cls.ASCII_A)
            for number in numbers
        )

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext using the Hill Cipher.

        Formula:
            C = K * P mod 26
        """

        processed_plaintext = self._preprocess_text(plaintext)
        padded_plaintext = self._pad_text(processed_plaintext)

        ciphertext = []

        for i in range(0, len(padded_plaintext), self.BLOCK_SIZE):
            block = padded_plaintext[i:i + self.BLOCK_SIZE]
            number_block = self._text_to_numbers(block)

            encrypted_numbers = self._matrix_multiply(
                self.key_matrix,
                number_block
            )

            encrypted_text = self._numbers_to_text(encrypted_numbers)
            ciphertext.append(encrypted_text)

        return "".join(ciphertext)

    def decrypt(self, ciphertext: str, remove_padding: bool = False) -> str:
        """
        Decrypt ciphertext using the Hill Cipher.

        Formula:
            P = K^-1 * C mod 26

        Args:
            ciphertext: The encrypted text.
            remove_padding: If True, removes trailing X characters.
                            Use carefully because a real message may naturally end in X.
        """

        processed_ciphertext = self._preprocess_text(ciphertext)

        if len(processed_ciphertext) % self.BLOCK_SIZE != 0:
            raise ValueError("Ciphertext length must be even for a 2x2 Hill Cipher.")

        plaintext = []

        for i in range(0, len(processed_ciphertext), self.BLOCK_SIZE):
            block = processed_ciphertext[i:i + self.BLOCK_SIZE]
            number_block = self._text_to_numbers(block)

            decrypted_numbers = self._matrix_multiply(
                self.inverse_matrix,
                number_block
            )

            decrypted_text = self._numbers_to_text(decrypted_numbers)
            plaintext.append(decrypted_text)

        decrypted_plaintext = "".join(plaintext)

        if remove_padding:
            decrypted_plaintext = decrypted_plaintext.rstrip("X")

        return decrypted_plaintext

    def print_matrices(self) -> None:
        """
        Print the encryption key matrix and decryption inverse matrix.
        """

        print("Encryption Key Matrix:")
        for row in self.key_matrix:
            print(f"  {row}")

        print("\nDecryption Key Matrix / Inverse Matrix:")
        for row in self.inverse_matrix:
            print(f"  {row}")


def run_demo() -> None:
    """
    Run example tests for the Hill Cipher.
    """

    print("=" * 60)
    print("HILL CIPHER DEMONSTRATION")
    print("=" * 60)

    examples = [
        {
            "key_matrix": [[5, 8], [17, 3]],
            "plaintext": "hello"
        },
        {
            "key_matrix": [[3, 3], [2, 5]],
            "plaintext": "cryptography"
        },
        {
            "key_matrix": [[7, 8], [11, 11]],
            "plaintext": "linear algebra"
        }
    ]

    for index, example in enumerate(examples, start=1):
        print(f"\nExample {index}")
        print("-" * 60)

        key_matrix = example["key_matrix"]
        plaintext = example["plaintext"]

        try:
            cipher = HillCipher(key_matrix)

            processed_plaintext = HillCipher._preprocess_text(plaintext)
            padded_plaintext = HillCipher._pad_text(processed_plaintext)

            ciphertext = cipher.encrypt(plaintext)
            decrypted_text = cipher.decrypt(ciphertext)

            print(f"Key Matrix:          {key_matrix}")
            cipher.print_matrices()

            print(f"\nOriginal Plaintext:  {plaintext}")
            print(f"Processed Plaintext: {processed_plaintext}")
            print(f"Padded Plaintext:    {padded_plaintext}")
            print(f"Ciphertext:          {ciphertext}")
            print(f"Decrypted Text:      {decrypted_text}")
            print(f"Successful Match:    {padded_plaintext == decrypted_text}")

        except (ValueError, TypeError) as error:
            print(f"Error: {error}")

    print("\nInvalid Key Matrix Test")
    print("-" * 60)

    try:
        invalid_key = [[1, 2], [2, 4]]
        print(f"Trying key matrix: {invalid_key}")
        HillCipher(invalid_key)

    except ValueError as error:
        print(f"Error: {error}")


if __name__ == "__main__":
    run_demo()
