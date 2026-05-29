"""
Hill Cipher Implementation

The Hill cipher is a polygraphic substitution cipher that encrypts blocks of letters
using linear algebra. It uses matrix multiplication in modular arithmetic (mod 26).

Encryption: C = (K * P) mod 26
Decryption: P = (K^-1 * C) mod 26

Where:
- K is the encryption key matrix (must be invertible mod 26)
- P is the plaintext block vector
- C is the ciphertext block vector
"""

import math
from typing import List, Tuple


class HillCipher:
    """Hill Cipher encryption and decryption using 2x2 matrices."""
    
    def __init__(self, key_matrix):
        """
        Initialize the Hill Cipher with a 2x2 key matrix.
        
        Args:
            key_matrix: 2x2 list/tuple representing the encryption key
                       Must be invertible mod 26
                       
        Raises:
            ValueError: If matrix is not invertible mod 26
        """
        if len(key_matrix) != 2 or len(key_matrix[0]) != 2 or len(key_matrix[1]) != 2:
            raise ValueError("Key matrix must be 2x2")
        
        self.key_matrix = [list(row) for row in key_matrix]
        
        # Check if matrix is invertible mod 26
        det = self._matrix_determinant(self.key_matrix)
        det_mod = det % 26
        
        if math.gcd(det_mod, 26) != 1:
            raise ValueError(f"Matrix determinant ({det}) is not invertible mod 26")
        
        # Calculate inverse matrix
        self.inverse_matrix = self._matrix_inverse(self.key_matrix)
    
    @staticmethod
    def _matrix_determinant(matrix):
        """Calculate determinant of 2x2 matrix."""
        return (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0])
    
    @staticmethod
    def _mod_inverse(a, m):
        """
        Calculate modular multiplicative inverse of a mod m.
        
        Args:
            a: Number to find inverse for
            m: Modulus
            
        Returns:
            Modular multiplicative inverse of a mod m
        """
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        gcd, x, _ = extended_gcd(a % m, m)
        if gcd != 1:
            raise ValueError(f"Modular inverse does not exist for {a} mod {m}")
        return (x % m + m) % m
    
    def _matrix_inverse(self, matrix):
        """
        Calculate inverse of 2x2 matrix in modular arithmetic (mod 26).
        
        For 2x2 matrix [[a,b],[c,d]], the inverse is:
        (1/det) * [[d,-b],[-c,a]] mod 26
        """
        det = self._matrix_determinant(matrix)
        det_mod = det % 26
        det_inv = self._mod_inverse(det_mod, 26)
        
        a, b = matrix[0][0], matrix[0][1]
        c, d = matrix[1][0], matrix[1][1]
        
        inverse = [
            [(det_inv * d) % 26, (-det_inv * b) % 26],
            [(-det_inv * c) % 26, (det_inv * a) % 26]
        ]
        
        return inverse
    
    @staticmethod
    def _matrix_multiply(matrix, vector):
        """Multiply 2x2 matrix with 2x1 vector in mod 26."""
        result = []
        for i in range(2):
            val = (matrix[i][0] * vector[0] + matrix[i][1] * vector[1]) % 26
            result.append(val)
        return result
    
    @staticmethod
    def _preprocess_text(text):
        """Preprocess text: convert to uppercase and remove non-alphabetic characters."""
        return ''.join(char.upper() for char in text if char.isalpha())
    
    @staticmethod
    def _pad_text(text, block_size=2):
        """Pad text with 'X' if length is not multiple of block size."""
        if len(text) % block_size != 0:
            text += 'X' * (block_size - len(text) % block_size)
        return text
    
    def encrypt(self, plaintext):
        """
        Encrypt plaintext using Hill Cipher.
        
        Args:
            plaintext: Text to encrypt
            
        Returns:
            Encrypted text (uppercase, no spaces)
        """
        plaintext = self._preprocess_text(plaintext)
        plaintext = self._pad_text(plaintext, block_size=2)
        
        ciphertext = []
        
        # Process text in blocks of 2
        for i in range(0, len(plaintext), 2):
            # Convert characters to numbers (A=0, B=1, ..., Z=25)
            block = [ord(plaintext[i]) - ord('A'), ord(plaintext[i+1]) - ord('A')]
            
            # Apply encryption: C = K * P mod 26
            encrypted_block = self._matrix_multiply(self.key_matrix, block)
            
            # Convert back to characters
            ciphertext.append(chr(encrypted_block[0] + ord('A')))
            ciphertext.append(chr(encrypted_block[1] + ord('A')))
        
        return ''.join(ciphertext)
    
    def decrypt(self, ciphertext):
        """
        Decrypt ciphertext using Hill Cipher.
        
        Args:
            ciphertext: Text to decrypt
            
        Returns:
            Decrypted text (uppercase, no spaces)
        """
        ciphertext = self._preprocess_text(ciphertext)
        
        if len(ciphertext) % 2 != 0:
            raise ValueError("Ciphertext length must be even")
        
        plaintext = []
        
        # Process text in blocks of 2
        for i in range(0, len(ciphertext), 2):
            # Convert characters to numbers
            block = [ord(ciphertext[i]) - ord('A'), ord(ciphertext[i+1]) - ord('A')]
            
            # Apply decryption: P = K^-1 * C mod 26
            decrypted_block = self._matrix_multiply(self.inverse_matrix, block)
            
            # Convert back to characters
            plaintext.append(chr(decrypted_block[0] + ord('A')))
            plaintext.append(chr(decrypted_block[1] + ord('A')))
        
        return ''.join(plaintext)
    
    def print_keys(self):
        """Print encryption and decryption key matrices."""
        print("Encryption Key Matrix:")
        for row in self.key_matrix:
            print(f"  {row}")
        print("\nDecryption Key Matrix (Inverse):")
        for row in self.inverse_matrix:
            print(f"  {row}")


# Example usage and testing
if __name__ == "__main__":
    print("=" * 60)
    print("HILL CIPHER DEMONSTRATION")
    print("=" * 60)
    
    # Example 1: Using key matrix [[5, 8], [17, 3]]
    print("\nExample 1: Key Matrix [[5, 8], [17, 3]]")
    try:
        key_matrix_1 = [[5, 8], [17, 3]]
        cipher1 = HillCipher(key_matrix_1)
        cipher1.print_keys()
        
        plaintext1 = "hello"
        ciphertext1 = cipher1.encrypt(plaintext1)
        decrypted1 = cipher1.decrypt(ciphertext1)
        
        print(f"\nPlaintext:  {plaintext1}")
        print(f"Ciphertext: {ciphertext1}")
        print(f"Decrypted:  {decrypted1}")
        
    except ValueError as e:
        print(f"Error: {e}")
    
    # Example 2: Using key matrix [[6, 24], [13, 16]]
    print("\n" + "=" * 60)
    print("Example 2: Key Matrix [[6, 24], [13, 16]]")
    try:
        key_matrix_2 = [[6, 24], [13, 16]]
        cipher2 = HillCipher(key_matrix_2)
        cipher2.print_keys()
        
        plaintext2 = "cryptography"
        ciphertext2 = cipher2.encrypt(plaintext2)
        decrypted2 = cipher2.decrypt(ciphertext2)
        
        print(f"\nPlaintext:  {plaintext2}")
        print(f"Ciphertext: {ciphertext2}")
        print(f"Decrypted:  {decrypted2}")
        
    except ValueError as e:
        print(f"Error: {e}")
    
    # Example 3: Invalid key (non-invertible)
    print("\n" + "=" * 60)
    print("Example 3: Invalid Key Matrix [[1, 2], [2, 4]]")
    try:
        key_matrix_3 = [[1, 2], [2, 4]]
        cipher3 = HillCipher(key_matrix_3)
    except ValueError as e:
        print(f"Error: {e}")
