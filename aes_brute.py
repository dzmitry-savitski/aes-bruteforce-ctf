#!/usr/bin/env python
import itertools
import os
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

ciphertext = b64decode("yzW81KkRaGOnaqiG7pr4AA==")
wordlist = "../../rockyou.txt"
known_plaintext = ""
print_all_ascii = True
charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
# charset = "0123456789abcdef"
# charset = ''.join(chr(x) for x in range(256))

def main():
    brute_dict()
    #brute_full(1, 10)


def brute_full(min, max):
    for len in range(min, max):
        brute(i)


def decrypt(key):
    iv = "\x00" * len(key)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # cipher = AES.new(key, AES.MODE_CBC)
    return cipher.decrypt(ciphertext)


def brute_dict():
    with open(wordlist) as infile:
        for pwd in infile:
            brute_key_length(pwd)


def brute(length):
    print "bruting length: {}".format(length)

    generator = itertools.product(charset, repeat=length)
    for password in generator:
        pwd = "".join(password)
        brute_key_length(pwd)


"""
check AES 128, 192 and 256
adjust key to right & left
"""
def brute_key_length(pwd):
    key = pwd.ljust(16, "\x00")
    try_pass(key)
    key = pwd.ljust(24, "\x00")
    try_pass(key)
    key = pwd.ljust(32, "\x00")
    try_pass(key)
    key = pwd.rjust(16, "\x00")
    try_pass(key)
    key = pwd.rjust(24, "\x00")
    try_pass(key)
    key = pwd.rjust(32, "\x00")
    try_pass(key)


def try_pass(key):
    try:
        result = decrypt(key)
        if (print_all_ascii and is_ascii(result)) or (known_plaintext and known_plaintext in result):
            print "[b64 key: {}]: {}".format(b64encode(key), result)
            # beep()
    except KeyboardInterrupt:
        raise
    except:
        pass


def beep():
    duration = 1  # second
    freq = 440  # Hz
    os.system('play --no-show-progress --null --channels 1 synth %s sine %f' % (duration, freq))


def is_ascii(s):
    return all(ord(c) < 128 for c in s)


if __name__ == "__main__":
    main()
