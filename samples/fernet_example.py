from cryptography.fernet import Fernet


def encrypt_note(note):
    key = Fernet.generate_key()
    return Fernet(key).encrypt(note)

