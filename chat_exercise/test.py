
WORD="EXXEGO EX SRGI"


def decp(word):
    word = word.upper()
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    for shift in range(26):
        new_word = ""
        for char in word:
            if char in alphabet:
                new_index = (alphabet.index(char) + shift) % 26
                new_word += alphabet[new_index]
            else:
                new_word += char
        print(f"Shift {shift}: {new_word}")


        if input("Press Enter to continue or type 'stop' to break: ").strip().lower() == "stop":
            break



decp(WORD)