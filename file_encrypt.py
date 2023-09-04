import tkinter as tk
from tkinter import filedialog
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class FileEncryptor:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryption")
        self.key = get_random_bytes(16)  # 128-bit (16 bytes) key for AES encryption

        self.label = tk.Label(root, text="Select a file to encrypt:")
        self.label.pack()

        self.encrypt_button = tk.Button(root, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(root, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_button.pack()

    def encrypt_file(self):
        input_file = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if input_file:
            output_file = input_file + ".enc"
            self._process_file(input_file, output_file, encrypt=True)

    def decrypt_file(self):
        input_file = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
        if input_file:
            output_file = input_file[:-4]  # Remove the '.enc' extension
            self._process_file(input_file, output_file, encrypt=False)

    def _process_file(self, input_file, output_file, encrypt=True):
        cipher = AES.new(self.key, AES.MODE_EAX)

        with open(input_file, 'rb') as file:
            data = file.read()

        if encrypt:
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(data)
            with open(output_file, 'wb') as file:
                file.write(nonce)
                file.write(tag)
                file.write(ciphertext)
            print("File encrypted.")
        else:
            nonce = data[:16]
            tag = data[16:32]
            ciphertext = data[32:]

            cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext)

            with open(output_file, 'wb') as file:
                file.write(plaintext)
            print("File decrypted.")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptor(root)
    root.mainloop()
