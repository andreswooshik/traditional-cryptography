"""
Affine Cipher Implementation

The Affine Cipher is a substitution cipher that encrypts letters using:

    E(x) = (a * x + b) mod 26
    D(y) = a_inverse * (y - b) mod 26

Where:
- x is the plaintext letter position: A=0, B=1, ..., Z=25
- y is the ciphertext letter position
- a and b are the keys
- gcd(a, 26) must be 1 so decryption is possible
"""

import math


class AffineCipher:
    """A simple and clean Affine Cipher implementation."""

    ALPHABET_SIZE = 26
    ASCII_A = ord('A')
    VALID_A_VALUES = (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25)

    def __init__(self, a: int, b: int):
        """
        Initialize the Affine Cipher with keys a and b.

        Args:
            a (int): Multiplier key. Must be coprime with 26.
            b (int): Additive key.

        Raises:
            TypeError: If a or b is not an integer.
            ValueError: If gcd(a, 26) is not equal to 1.
        """

        if not isinstance(a, int) or not isinstance(b, int):
            raise TypeError("Keys 'a' and 'b' must be integers.")

        # Normalize keys to fit within modulo 26
        self.a = a % self.ALPHABET_SIZE
        self.b = b % self.ALPHABET_SIZE

        if math.gcd(self.a, self.ALPHABET_SIZE) != 1:
            raise ValueError(
                f"Invalid key 'a': gcd({self.a}, 26) must be 1.\n"
                f"Valid values for a are: {self.VALID_A_VALUES}"
            )

        self.a_inverse = self._mod_inverse(self.a, self.ALPHABET_SIZE)

    @staticmethod
    def _mod_inverse(a: int, m: int) -> int:
        """
        Calculate the modular multiplicative inverse of a mod m.

        Example:
            If a = 5 and m = 26, the inverse is 21
            because (5 * 21) mod 26 = 1.
        """

        def extended_gcd(x: int, y: int):
            if x == 0:
                return y, 0, 1

            gcd, x1, y1 = extended_gcd(y % x, x)
            new_x = y1 - (y // x) * x1
            new_y = x1

            return gcd, new_x, new_y

        gcd, inverse, _ = extended_gcd(a, m)

        if gcd != 1:
            raise ValueError(f"No modular inverse exists for {a} mod {m}.")

        return inverse % m

    @staticmethod
    def _preprocess_text(text: str) -> str:
        """
        Convert text to uppercase and keep only English letters A-Z.

        This avoids problems with spaces, numbers, punctuation,
        and non-English letters.
        """

        if not isinstance(text, str):
            raise TypeError("Text must be a string.")

        return ''.join(
            char.upper()
            for char in text
            if 'A' <= char.upper() <= 'Z'
        )

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext using the Affine Cipher.

        Formula:
            E(x) = (a * x + b) mod 26
        """

        plaintext = self._preprocess_text(plaintext)
        ciphertext = []

        for char in plaintext:
            x = ord(char) - self.ASCII_A
            y = (self.a * x + self.b) % self.ALPHABET_SIZE
            encrypted_char = chr(y + self.ASCII_A)
            ciphertext.append(encrypted_char)

        return ''.join(ciphertext)

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt ciphertext using the Affine Cipher.

        Formula:
            D(y) = a_inverse * (y - b) mod 26
        """

        ciphertext = self._preprocess_text(ciphertext)
        plaintext = []

        for char in ciphertext:
            y = ord(char) - self.ASCII_A
            x = (self.a_inverse * (y - self.b)) % self.ALPHABET_SIZE
            decrypted_char = chr(x + self.ASCII_A)
            plaintext.append(decrypted_char)

        return ''.join(plaintext)


def run_demo():
    """Run sample encryption and decryption tests."""

    print("=" * 60)
    print("AFFINE CIPHER DEMONSTRATION")
    print("=" * 60)

    examples = [
        {
            "a": 5,
            "b": 8,
            "plaintext": "hello world"
        },
        {
            "a": 3,
            "b": 5,
            "plaintext": "the quick brown fox"
        },
        {
            "a": 7,
            "b": 2,
            "plaintext": "cryptography is fun"
        }
    ]

    for index, example in enumerate(examples, start=1):
        print(f"\nExample {index}: a={example['a']}, b={example['b']}")

        cipher = AffineCipher(example["a"], example["b"])

        plaintext = example["plaintext"]
        ciphertext = cipher.encrypt(plaintext)
        decrypted_text = cipher.decrypt(ciphertext)
        processed_plaintext = AffineCipher._preprocess_text(plaintext)

        print(f"Original Plaintext:  {plaintext}")
        print(f"Processed Plaintext: {processed_plaintext}")
        print(f"Ciphertext:          {ciphertext}")
        print(f"Decrypted Text:      {decrypted_text}")
        print(f"Successful Match:    {processed_plaintext == decrypted_text}")

    print("\nInvalid Key Test: a=4, b=5")

    try:
        invalid_cipher = AffineCipher(4, 5)
    except ValueError as error:
        print(f"Error: {error}")


if __name__ == "__main__":
    run_demo()
