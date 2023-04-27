# CryptoCapy Ransomware WIP

Capybara themed Ransomware created for Linux. It encrypts all files in a provided directory and it's children with a asymmetric RSA2048 encrypted symmetric Fernet key.

[![Travis branch](https://img.shields.io/cran/l/devtools.svg)](https://github.com/its0v3r/CryptoCapy-Ransomware/blob/main/LICENSE)
[![Travis branch](https://img.shields.io/badge/made%20with-%3C3-red.svg)](https://github.com/its0v3r/CryptoCapy-Ransomware)

# Features

- [x] Asymmetric Encryption with RSA2048 + Symmetric Encryption with Fernet
- [x] Deletes original files and creates a new one with all original data encrypted
- [x] Encrypted files have a random 25 character name
- [x] Encrypted files a .capybara extension
- [x] Fully working decryption without breaking any files and restoring original file names and extensions
- [x] File name and extension are stored inside each encrypted file, encoded in base64 and encrypted with the fernet key

# To do

- [ ] Daemon
- [ ] Autorun
- [ ] Dropper
- [ ] Backdoor
- [ ] Threading
- [ ] C2C Server
- [ ] Persistence
- [ ] Compiled version
- [ ] Bypass security measures
- [ ] ScreenLock/Wallpaper Change
- [ ] Block system functionalities

# Security measures

The CryptoCapy will only encrypt a defined path in the cryptocapy.py file, so, just don't place an important path in that space and you will be Ok! If for some reason you passed an wrong directory and encrypted it, don't panic, just change the "action" inside the cryptocapy.py file from "e" to "d". Be careful to don't delete the keys!

# How to use the Ransomware?

- Inside the file, define what path you want to work on, and if you want the action to be encrypt files (e) or decrypt files (d);
- This code is meant to work with Python3.

Example 1 - Running the CryptoCapy Ransomware:

```
python3 cryptocapy.py
```
