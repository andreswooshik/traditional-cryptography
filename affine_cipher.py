"""
Affine Cipher Implementation

The Affine cipher is a substitution cipher that encrypts text using a linear function:
E(x) = (ax + b) mod 26

Where:
- x is the position of the letter (A=0, B=1, ..., Z=25)
- a and b are the encryption keys
- gcd(a, 26) must equal 1 for the cipher to be reversible
"""

import math


class AffineCipher:
    """Affine Cipher encryption and decryption."""
    
    def __init__(self, a, b):
        """
        Initialize the Affine Cipher with keys a and b.
        
        Args:
            a: Multiplier key (must satisfy gcd(a, 26) = 1)
            b: Additive key (0-25)
            
        Raises:
            ValueError: If gcd(a, 26) != 1
        """
        if math.gcd(a, 26) != 1:
            raise ValueError(f"Invalid key 'a': gcd({a}, 26) must equal 1")
        
        self.a = a
        self.b = b
        self.a_inverse = self._mod_inverse(a, 26)
    
    @staticmethod
    def _mod_inverse(a, m):
        """
        Calculate modular multiplicative inverse of a mod m using Extended Euclidean Algorithm.
        
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
    
    @staticmethod
    def _preprocess_text(text):
        """
        Preprocess text: convert to uppercase and remove non-alphabetic characters.
        
        Args:
            text: Text to preprocess
            
        Returns:
            Processed text containing only uppercase letters
        """
        return ''.join(char.upper() for char in text if char.isalpha())
    
    def encrypt(self, plaintext):
        """
        Encrypt plaintext using Affine Cipher.
        
        Args:
            plaintext: Text to encrypt
            
        Returns:
            Encrypted text (uppercase, no spaces)
        """
        plaintext = self._preprocess_text(plaintext)
        ciphertext = []
        
        for char in plaintext:
            x = ord(char) - ord('A')
            y = (self.a * x + self.b) % 26
            ciphertext.append(chr(y + ord('A')))
        
        return ''.join(ciphertext)
    
    def decrypt(self, ciphertext):
        """
        Decrypt ciphertext using Affine Cipher.
        
        Args:
            ciphertext: Text to decrypt
            
        Returns:
            Decrypted text (uppercase, no spaces)
        """
        ciphertext = self._preprocess_text(ciphertext)
        plaintext = []
        
        for char in ciphertext:
            y = ord(char) - ord('A')
            x = (self.a_inverse * (y - self.b)) % 26
            plaintext.append(chr(x + ord('A')))
        
        return ''.join(plaintext)


# Example usage and testing
if __name__ == "__main__":
    # Valid keys: a must be coprime with 26
    # Valid values for a: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25
    
    print("=" * 60)
    print("AFFINE CIPHER DEMONSTRATION")
    print("=" * 60)
    
    # Example 1
    print("\nExample 1: a=5, b=8")
    cipher1 = AffineCipher(5, 8)
    
    plaintext1 = "hello world"
    ciphertext1 = cipher1.encrypt(plaintext1)
    decrypted1 = cipher1.decrypt(ciphertext1)
    
    print(f"Plaintext:  {plaintext1}")
    print(f"Ciphertext: {ciphertext1}")
    print(f"Decrypted:  {decrypted1}")
    print(f"Match: {plaintext1.upper().replace(' ', '') == decrypted1}")
    
    # Example 2
    print("\nExample 2: a=3, b=5")
    cipher2 = AffineCipher(3, 5)
    
    plaintext2 = "the quick brown fox"
    ciphertext2 = cipher2.encrypt(plaintext2)
    decrypted2 = cipher2.decrypt(ciphertext2)
    
    print(f"Plaintext:  {plaintext2}")
    print(f"Ciphertext: {ciphertext2}")
    print(f"Decrypted:  {decrypted2}")
    print(f"Match: {plaintext2.upper().replace(' ', '') == decrypted2}")
    
    # Example 3: Invalid key
    print("\nExample 3: Invalid key (a=4, b=5)")
    try:
        cipher3 = AffineCipher(4, 5)
    except ValueError as e:
        print(f"Error: {e}")
