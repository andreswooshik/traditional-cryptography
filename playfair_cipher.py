
"""
Playfair Cipher and Pigpen Cipher Demonstration

This program includes:
1. Playfair Cipher encryption and decryption
2. Pigpen Cipher encryption and decryption

Scope:
- Uses A-Z letters
- Ignores case
- Playfair removes spaces and punctuation
- Pigpen preserves spaces
"""


class PlayfairCipher:
    """
    Playfair Cipher implementation.

    The Playfair Cipher uses a 5x5 keys square.
    I and J are combined because the square only has 25 spaces.
    """

    ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # J is removed
    SIZE = 5

    def __init__(self, key: str):
        self.key = self._clean_text(key).replace("J", "I")

        if not self.key:
            raise ValueError("Key must contain at least one letter.")

        self.square = self._build_square()
        self.positions = self._get_positions()

    @staticmethod
    def _clean_text(text: str) -> str:
        """
        Convert text to uppercase and keep only A-Z letters.
        """

        return "".join(
            char.upper()
            for char in text
            if "A" <= char.upper() <= "Z"
        )

    def _build_square(self):
        """
        Build the 5x5 Playfair key square using the key.
        """

        used_letters = []

        for char in self.key + self.ALPHABET:
            if char == "J":
                char = "I"

            if char not in used_letters and char in self.ALPHABET:
                used_letters.append(char)

        square = []

        for i in range(0, 25, 5):
            square.append(used_letters[i:i + 5])

        return square

    def _get_positions(self):
        """
        Store the row and column position of each letter.
        """

        positions = {}

        for row in range(self.SIZE):
            for col in range(self.SIZE):
                letter = self.square[row][col]
                positions[letter] = (row, col)

        return positions

    def print_square(self):
        """
        Display the Playfair key square.
        """

        print("\nPlayfair Key Square:")
        for row in self.square:
            print(" ".join(row))

    def _prepare_plaintext(self, plaintext: str):
        """
        Prepare plaintext by:
        - Removing non-letters
        - Replacing J with I
        - Splitting into pairs
        - Adding X between repeated letters
        - Adding X at the end if needed
        """

        text = self._clean_text(plaintext).replace("J", "I")
        pairs = []
        i = 0

        while i < len(text):
            first = text[i]

            if i + 1 >= len(text):
                second = "X"
                i += 1
            else:
                second = text[i + 1]

                if first == second:
                    second = "X"
                    i += 1
                else:
                    i += 2

            pairs.append(first + second)

        return pairs

    def _split_ciphertext(self, ciphertext: str):
        """
        Split ciphertext into letter pairs.
        """

        text = self._clean_text(ciphertext).replace("J", "I")

        if len(text) % 2 != 0:
            raise ValueError("Ciphertext must have an even number of letters.")

        pairs = []

        for i in range(0, len(text), 2):
            pairs.append(text[i:i + 2])

        return pairs

    def _process_pair(self, pair: str, mode: str) -> str:
        """
        Encrypt or decrypt one pair of letters.
        """

        first, second = pair

        row1, col1 = self.positions[first]
        row2, col2 = self.positions[second]

        # Rule 1: Same row
        if row1 == row2:
            if mode == "encrypt":
                return (
                    self.square[row1][(col1 + 1) % self.SIZE] +
                    self.square[row2][(col2 + 1) % self.SIZE]
                )
            else:
                return (
                    self.square[row1][(col1 - 1) % self.SIZE] +
                    self.square[row2][(col2 - 1) % self.SIZE]
                )

        # Rule 2: Same column
        if col1 == col2:
            if mode == "encrypt":
                return (
                    self.square[(row1 + 1) % self.SIZE][col1] +
                    self.square[(row2 + 1) % self.SIZE][col2]
                )
            else:
                return (
                    self.square[(row1 - 1) % self.SIZE][col1] +
                    self.square[(row2 - 1) % self.SIZE][col2]
                )

        # Rule 3: Rectangle rule
        return self.square[row1][col2] + self.square[row2][col1]

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext using the Playfair Cipher.
        """

        pairs = self._prepare_plaintext(plaintext)
        ciphertext = ""

        for pair in pairs:
            ciphertext += self._process_pair(pair, "encrypt")

        return ciphertext

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt ciphertext using the Playfair Cipher.
        """

        pairs = self._split_ciphertext(ciphertext)
        plaintext = ""

        for pair in pairs:
            plaintext += self._process_pair(pair, "decrypt")

        return plaintext


class PigpenCipher:
    """
    Pigpen Cipher implementation.

    This uses custom Pigpen-like symbols.
    Each letter A-Z has one unique symbol.
    Spaces are preserved.
    """

    PIGPEN_MAP = {
        "A": "⌜", "B": "⌝", "C": "⌞", "D": "⌟", "E": "□",
        "F": "◰", "G": "◱", "H": "◲", "I": "◳", "J": "◇",
        "K": "◈", "L": "◆", "M": "△", "N": "▲", "O": "▽",
        "P": "▼", "Q": "◁", "R": "◀", "S": "▷", "T": "▶",
        "U": "○", "V": "●", "W": "◌", "X": "◍", "Y": "◎",
        "Z": "⊙"
    }

    REVERSE_MAP = {symbol: letter for letter, symbol in PIGPEN_MAP.items()}

    @classmethod
    def encrypt(cls, plaintext: str) -> str:
        """
        Convert plaintext A-Z into Pigpen symbols.
        Spaces are preserved.
        """

        result = ""

        for char in plaintext.upper():
            if "A" <= char <= "Z":
                result += cls.PIGPEN_MAP[char]
            elif char == " ":
                result += " "
            # Other characters are ignored

        return result

    @classmethod
    def decrypt(cls, ciphertext: str) -> str:
        """
        Convert Pigpen symbols back into plaintext.
        Spaces are preserved.
        """

        result = ""

        for symbol in ciphertext:
            if symbol in cls.REVERSE_MAP:
                result += cls.REVERSE_MAP[symbol]
            elif symbol == " ":
                result += " "
            # Unknown symbols are ignored

        return result

    @classmethod
    def print_symbol_guide(cls):
        """
        Display the Pigpen symbol guide.
        """

        print("\nPigpen Symbol Guide:")
        print("-" * 30)

        for letter, symbol in cls.PIGPEN_MAP.items():
            print(f"{letter} = {symbol}")


def run_playfair_demo():
    """
    Run a sample Playfair Cipher demonstration.
    """

    print("=" * 60)
    print("PLAYFAIR CIPHER DEMONSTRATION")
    print("=" * 60)

    key = "MONARCHY"
    plaintext = "instruments"

    cipher = PlayfairCipher(key)

    encrypted = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(encrypted)

    print(f"Key:                {key}")
    cipher.print_square()

    print(f"\nOriginal Plaintext: {plaintext}")
    print(f"Ciphertext:         {encrypted}")
    print(f"Decrypted Text:     {decrypted}")

    print("\nNote: The decrypted text may include X as padding or filler.")


def run_pigpen_demo():
    """
    Run a sample Pigpen Cipher demonstration.
    """

    print("=" * 60)
    print("PIGPEN CIPHER DEMONSTRATION")
    print("=" * 60)

    plaintext = "HELLO TEAM F"

    encrypted = PigpenCipher.encrypt(plaintext)
    decrypted = PigpenCipher.decrypt(encrypted)

    PigpenCipher.print_symbol_guide()

    print(f"\nOriginal Plaintext: {plaintext}")
    print(f"Pigpen Symbols:     {encrypted}")
    print(f"Decrypted Text:     {decrypted}")


def main_menu():
    """
    Main menu for user interaction.
    """

    while True:
        print("\n" + "=" * 60)
        print("CLASSICAL CIPHER PROGRAM")
        print("=" * 60)
        print("1 - Playfair Encrypt")
        print("2 - Playfair Decrypt")
        print("3 - Pigpen Encrypt")
        print("4 - Pigpen Decrypt")
        print("5 - Show Pigpen Symbol Guide")
        print("6 - Run Sample Demo")
        print("0 - Exit")

        choice = input("Enter your choice: ")

        try:
            if choice == "1":
                key = input("Enter Playfair key: ")
                plaintext = input("Enter plaintext: ")

                cipher = PlayfairCipher(key)
                cipher.print_square()

                print("\nEncrypted Text:", cipher.encrypt(plaintext))

            elif choice == "2":
                key = input("Enter Playfair key: ")
                ciphertext = input("Enter ciphertext: ")

                cipher = PlayfairCipher(key)
                cipher.print_square()

                print("\nDecrypted Text:", cipher.decrypt(ciphertext))

            elif choice == "3":
                plaintext = input("Enter plaintext: ")

                print("\nPigpen Symbols:", PigpenCipher.encrypt(plaintext))

            elif choice == "4":
                ciphertext = input("Enter Pigpen symbols: ")

                print("\nDecrypted Text:", PigpenCipher.decrypt(ciphertext))

            elif choice == "5":
                PigpenCipher.print_symbol_guide()

            elif choice == "6":
                run_playfair_demo()
                print()
                run_pigpen_demo()

            elif choice == "0":
                print("Program ended.")
                break

            else:
                print("Invalid choice. Please try again.")

        except ValueError as error:
            print("Error:", error)


if __name__ == "__main__":
    main_menu()
