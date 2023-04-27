# Basic Ransomware

## What is this script?

This is a simple Ransomware that encrypts/decrypts all files in a provided directory and it's children.


## Security measures

This Ransomware can only be run by executing the basicransomware.py file with some arguments in the terminal, so you are 100% safe to download this file in your computer. The only thing you need to be careful it's when executing the ransomware: be aware that it will encrypt all the files in a provided directory and it's children, so just don't provide an wrong directory that you don't want the files to be encrypted! If you accidentally encrypt the files in a wrong directory, don't panic, just execute the same command as you did before, but changing the argument from "--encrypt" to "--decrypt".

## How to use the Ransomware?

- The user can chose which directory he wants to encrypt/decrypt it's files (-p, --path) and the operation he wants to run (-e, --encrypt) (-d, --decrypt);
- This code is meant to work with Python3.

Example 1 - Encrypting all files path and it's children:

```
python3 basicransomware.py -p "/home/user/Documents" -e
```

Example 2 - Decrypting all files path and it's children:

```
python3 basicransomware.py -p "/home/user/Documents" -d
```