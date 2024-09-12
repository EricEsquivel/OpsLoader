from Crypto.Cipher import ARC4
import sys

def rc4_encrypt(key, plaintext):
    """
    Encrypts plaintext using RC4 with the given key.
    
    :param key: The encryption key (bytes)
    :param plaintext: The data to encrypt (bytes)
    :return: Encrypted data (bytes)
    """
    cipher = ARC4.new(key)
    return cipher.encrypt(plaintext)

def read_file(file_path):
    """
    Reads the content of a file as bytes.
    
    :param file_path: Path to the input file
    :return: File content as bytes
    """
    with open(file_path, 'rb') as f:
        return f.read()

def write_file(file_path, data):
    """
    Writes bytes data to a file.
    
    :param file_path: Path to the output file
    :param data: Data to write (bytes)
    """
    with open(file_path, 'wb') as f:
        f.write(data)

def main():
    if len(sys.argv) != 4:
        print("Usage: python rc4_encrypt.py <input_file> <output_file> <key>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    key = sys.argv[3].encode('utf-8')  # Convert the key to bytes

    if len(key) == 0:
        print("Error: Key cannot be empty.")
        sys.exit(1)

    plaintext = read_file(input_file)
    encrypted = rc4_encrypt(key, plaintext)
    write_file(output_file, encrypted)
    print(f"Encryption complete. Encrypted data written to {output_file}")

if __name__ == "__main__":
    main()

