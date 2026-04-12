from Crypto.Cipher import AES
import json
import base64
import struct
import binascii
import random
import codecs

def makebyte(x):
    if isinstance(x, bytes):
        return x
    return codecs.latin_1_encode(x)[0]

def makestring(x):
    if isinstance(x, str):
        return x
    return codecs.latin_1_decode(x)[0]

def aes_cbc_encrypt(data, key):
    aes_cipher = AES.new(key, AES.MODE_CBC, b'\x00' * 16)
    return aes_cipher.encrypt(data)

def aes_cbc_decrypt(data, key):
    aes_cipher = AES.new(key, AES.MODE_CBC, b'\x00' * 16)
    return aes_cipher.decrypt(data)

def aes_cbc_encrypt_a32(data, key):
    return str_to_a32(aes_cbc_encrypt(a32_to_str(data), a32_to_str(key)))

def aes_cbc_decrypt_a32(data, key):
    return str_to_a32(aes_cbc_decrypt(a32_to_str(data), a32_to_str(key)))

def stringhash(str, aeskey):
    s32 = str_to_a32(str)
    h32 = [0, 0, 0, 0]
    for i in range(len(s32)):
        h32[i % 4] ^= s32[i]
    for r in range(16384):
        h32 = aes_cbc_encrypt_a32(h32, aeskey)
    return a32_to_base64((h32[0], h32[2]))

def prepare_key(arr):
    pkey = [2479122403, 2108737444, 3518906241, 22203222]
    for r in range(65536):
        for j in range(0, len(arr), 4):
            key = [0, 0, 0, 0]
            for i in range(4):
                if i + j < len(arr):
                    key[i] = arr[i + j]
            pkey = aes_cbc_encrypt_a32(pkey, key)
    return pkey

def encrypt_key(a, key):
    return sum((aes_cbc_encrypt_a32(a[i:i + 4], key) for i in range(0, len(a), 4)), ())

def decrypt_key(a, key):
    return sum((aes_cbc_decrypt_a32(a[i:i + 4], key) for i in range(0, len(a), 4)), ())

def encrypt_attr(attr, key):
    attr = makebyte('MEGA' + json.dumps(attr))
    if len(attr) % 16:
        attr += b'\x00' * (16 - len(attr) % 16)
    return aes_cbc_encrypt(attr, a32_to_str(key))

def decrypt_attr(attr, key):
    attr = aes_cbc_decrypt(attr, a32_to_str(key))
    attr = makestring(attr)
    attr = attr.rstrip('\x00')
    return json.loads(attr[4:]) if attr[:6] == 'MEGA{"' else False

def a32_to_str(a):
    return struct.pack('>%dI' % len(a), *a)

def str_to_a32(b):
    if isinstance(b, str):
        b = makebyte(b)
    if len(b) % 4:
        b += b'\x00' * (4 - len(b) % 4)
    return struct.unpack('>%dI' % (len(b) // 4), b)

def mpi_to_int(s):
    return int(binascii.hexlify(s[2:]), 16)

def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - b // a * y, y)

def modular_inverse(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def base64_url_decode(data):
    data += '=='[(2 - len(data) * 3) % 4:]
    for search, replace in (('-', '+'), ('_', '/'), (',', '')):
        data = data.replace(search, replace)
    return base64.b64decode(data)

def base64_to_a32(s):
    return str_to_a32(base64_url_decode(s))

def base64_url_encode(data):
    data = base64.b64encode(data)
    data = makestring(data)
    for search, replace in (('+', '-'), ('/', '_'), ('=', '')):
        data = data.replace(search, replace)
    return data

def a32_to_base64(a):
    return base64_url_encode(a32_to_str(a))

def get_chunks(size):
    p = 0
    s = 131072
    while p + s < size:
        yield (p, s)
        p += s
        if s < 1048576:
            s += 131072
    yield (p, size - p)

def make_id(length):
    text = ''
    possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    for i in range(length):
        text += random.choice(possible)
    return text