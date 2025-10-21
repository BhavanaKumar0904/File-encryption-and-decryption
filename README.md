File Encryption and Decryption Tool (Java)

A simple yet secure Java-based tool to encrypt and decrypt files using AES-256 encryption with password-based key derivation.
It ensures data privacy by generating a unique salt and initialization vector (IV) for every encryption process.

⚙️ Features

AES-256 encryption with CBC mode & PKCS5 padding

Password-based key derivation using PBKDF2WithHmacSHA256

Automatic generation of salt and IV for enhanced security

Safe password handling (memory wiped after use)

Works for any file type (text, images, PDFs, etc.)

🧠 How It Works

The user provides a password.

A salt and IV are randomly generated.

A key is derived using PBKDF2 and used for AES encryption.

The encrypted file stores a small header, salt, IV, and ciphertext.

During decryption, the same password reconstructs the key to recover the original file.




BASH

# Compile
javac Main.java

# Encrypt a file
java Main encrypt input.txt encrypted.bin

# Decrypt the file
java Main decrypt encrypted.bin output.txt

Enter password:
Encryption complete: encrypted.bin

Enter password:
Decryption complete: output.txt



🛡️ Tech Stack
Java (JDK 8+)

javax.crypto, java.security packages

