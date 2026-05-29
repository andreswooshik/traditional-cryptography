# Traditional Cryptography

A Python collection of classical cipher implementations for educational purposes. Explore historical encryption methods including the Affine Cipher, Hill Cipher, Playfair Cipher, and Pigpen Cipher.

## Overview

This repository contains clean, well-documented implementations of classic cryptographic algorithms that predate modern computer-based encryption. Each cipher is fully implemented with encryption and decryption capabilities.

## Ciphers Included

### 1. **Affine Cipher** (`affine_cipher.py`)

A substitution cipher using modular arithmetic for encryption and decryption.

**Formula:**
- Encryption: `E(x) = (a * x + b) mod 26`
- Decryption: `D(y) = a⁻¹ * (y - b) mod 26`

**Key Requirements:**
- `a` must be coprime with 26 (gcd(a, 26) = 1)
- Valid `a` values: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25
- `b` can be any integer 0-25

**Features:**
- Type checking for key validation
- Extended Euclidean Algorithm for modular inverse calculation
- Automatic text preprocessing (uppercase conversion, non-letter removal)

cipher = AffineCipher(5, 8)
ciphertext = cipher.encrypt("hello world")
plaintext = cipher.decrypt(ciphertext)
2. Hill Cipher (hill_cipher.py)
A polygraphic substitution cipher that encrypts text in blocks using matrix multiplication modulo 26.

Formula:

Encryption: C = (K * P) mod 26
Decryption: P = (K⁻¹ * C) mod 26
Key Requirements:

2×2 integer key matrix
Determinant must be coprime with 26
Matrix must be invertible modulo 26
Features:

2×2 matrix operations
Automatic text padding with 'X' for block alignment
Matrix inversion using Extended Euclidean Algorithm
Validation of key matrix invertibility
Example:

Python
cipher = HillCipher([[5, 8], [17, 3]])
ciphertext = cipher.encrypt("hello")
plaintext = cipher.decrypt(ciphertext)
3. Playfair Cipher (playfair_cipher.py)
A digraphic substitution cipher using a 5×5 key square for encrypting letter pairs.

Key Features:

5×5 key square (I and J combined)
Three encryption rules:
Same row: shift right (wraps around)
Same column: shift down (wraps around)
Rectangle: swap columns
Pair preparation with 'X' filler for repeated letters
Example:

Python
cipher = PlayfairCipher("MONARCHY")
ciphertext = cipher.encrypt("instruments")
plaintext = cipher.decrypt(ciphertext)
cipher.print_square()
4. Pigpen Cipher (playfair_cipher.py)
A geometric substitution cipher using unique symbols for each letter A-Z. Also includes an interactive menu for cipher operations.

Features:

Symbol-based encryption/decryption
Preserves spaces for readability
26 unique Unicode symbols mapping
Example:

Python
encrypted = PigpenCipher.encrypt("HELLO WORLD")
decrypted = PigpenCipher.decrypt(encrypted)
PigpenCipher.print_symbol_guide()
Usage
Running Demos
Each cipher file includes a demo function:

bash
python affine_cipher.py
python hill_cipher.py
python playfair_cipher.py  # Also includes interactive menu
Basic Usage
Python
from affine_cipher import AffineCipher
from hill_cipher import HillCipher
from playfair_cipher import PlayfairCipher, PigpenCipher

# Affine Cipher
aff = AffineCipher(5, 8)
print(aff.encrypt("cryptography"))

# Hill Cipher
hill = HillCipher([[3, 3], [2, 5]])
print(hill.encrypt("hello"))

# Playfair Cipher
pf = PlayfairCipher("SECRET")
print(pf.encrypt("attackatdawn"))

# Pigpen Cipher
print(PigpenCipher.encrypt("HELLO"))
File Structure
Code
.
├── affine_cipher.py       # Affine Cipher implementation
├── hill_cipher.py         # Hill Cipher implementation
├── playfair_cipher.py     # Playfair & Pigpen Cipher implementations
└── README.md              # This file
Technical Details
Text Preprocessing
All ciphers normalize input text by:

Converting to uppercase
Removing spaces, punctuation, and non-English letters
Preserving only A-Z characters
Error Handling
Each cipher includes validation for:

Invalid key formats and types
Keys that violate mathematical requirements
Malformed input text
Mathematical Operations
Extended Euclidean Algorithm: Used for modular inverse calculations
Matrix Operations: Hill Cipher uses 2×2 matrix multiplication modulo 26
Modular Arithmetic: All ciphers work in modulo 26 space
Requirements
Python 3.6+
No external dependencies
Educational Value
This repository demonstrates:

Classical cryptography concepts
Modular arithmetic applications
Matrix operations in cryptography
Python object-oriented design
Input validation and error handling
Implementation of historical algorithms
Notes
These ciphers are not suitable for real-world security and are presented for educational purposes only
Modern cryptography uses different approaches and should be used for actual data protection
Cipher outputs may contain padding characters (especially 'X') which should be removed manually if needed
License
This project is open source and available for educational use.

Authors
Created by: Ralf Andre Ebuna and Reiner Seldon Dela Cerna

For questions or improvements, feel free to open an issue or submit a pull request.
