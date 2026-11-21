"""Generate known-answer test vectors with an independent implementation.

Uses the Python `cryptography` package. Run: python3 -I tools/gen_vectors.py
"""
import base64
import json
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def b64url(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def str_to_a32(b):
    if len(b) % 4:
        b += b"\0" * (4 - len(b) % 4)
    return list(struct.unpack(">%dI" % (len(b) // 4), b))


def a32_to_bytes(a):
    return struct.pack(">%dI" % len(a), *a)


def aes_ecb_enc(key, data):
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(data) + e.finalize()


def prepare_key(arr):
    pkey = a32_to_bytes([0x93C467E3, 0x7DB0C7A4, 0xD1BE3F81, 0x0152CB56])
    for _ in range(0x10000):
        for j in range(0, len(arr), 4):
            key = [0, 0, 0, 0]
            for i in range(4):
                if i + j < len(arr):
                    key[i] = arr[i + j]
            pkey = aes_ecb_enc(a32_to_bytes(key), pkey)
    return pkey


def user_hash(email, pkey):
    s32 = str_to_a32(email.encode())
    h32 = [0, 0, 0, 0]
    for i, w in enumerate(s32):
        h32[i % 4] ^= w
    h = a32_to_bytes(h32)
    for _ in range(0x4000):
        h = aes_ecb_enc(pkey, h)
    a = str_to_a32(h)
    return b64url(a32_to_bytes([a[0], a[2]]))


out = {}
pw = "correct horse battery staple"
pk = prepare_key(str_to_a32(pw.encode()))
out["v1_password"] = pw
out["v1_prepared_key_hex"] = pk.hex()
out["v1_email"] = "Test.User@Example.com"
out["v1_user_hash"] = user_hash(out["v1_email"].lower(), pk)

salt = bytes(range(32))
kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=32, salt=salt, iterations=100000)
dk = kdf.derive(pw.encode())
out["v2_salt_b64url"] = b64url(salt)
out["v2_password_aes_hex"] = dk[:16].hex()
out["v2_user_hash"] = b64url(dk[16:])

key = bytes(range(16))
attr = b"MEGA" + json.dumps({"n": "hello.txt"}, separators=(",", ":")).encode()
attr += b"\0" * ((16 - len(attr) % 16) % 16)
e = Cipher(algorithms.AES(key), modes.CBC(b"\0" * 16)).encryptor()
out["attr_key_hex"] = key.hex()
out["attr_plain"] = '{"n":"hello.txt"}'
out["attr_b64url"] = b64url(e.update(attr) + e.finalize())

file_key = bytes((i * 7 + 3) % 256 for i in range(32))
k = str_to_a32(file_key)
aes_key = a32_to_bytes([k[0] ^ k[4], k[1] ^ k[5], k[2] ^ k[6], k[3] ^ k[7]])
nonce = a32_to_bytes([k[4], k[5]])
offset = 48
iv = nonce + struct.pack(">Q", offset // 16)
plain = bytes(i % 251 for i in range(100))
e = Cipher(algorithms.AES(aes_key), modes.CTR(iv)).encryptor()
out["file_key_b64url"] = b64url(file_key)
out["file_aes_key_hex"] = aes_key.hex()
out["file_nonce_hex"] = nonce.hex()
out["ctr_offset"] = offset
out["ctr_plain_hex"] = plain.hex()
out["ctr_cipher_hex"] = (e.update(plain) + e.finalize()).hex()

print(json.dumps(out, indent=2))


def megadownloader_link(plain, key_hex, folder):
    iv = bytes.fromhex("79F10A01844A0B27FF5B2D4E0ED3163E")
    data = plain.encode()
    data += b"\0" * ((16 - len(data) % 16) % 16)
    e = Cipher(algorithms.AES(bytes.fromhex(key_hex)), modes.CBC(iv)).encryptor()
    return ("mega://fenc2?" if folder else "mega://enc?") + b64url(e.update(data) + e.finalize())


print(json.dumps({
    "enc_file_link": megadownloader_link(
        "!AbCdEfGh!AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dw",
        "6B316F36416C2D316B7A3F217A30357958585858585858585858585858585858", False),
    "enc2_folder_link": megadownloader_link(
        "!FoLdEr12!AAECAwQFBgcICQoLDA0ODw",
        "ED1F4C200B35139806B260563B3D3876F011B4750F3A1A4A5EFD0BBE67554B44", True),
}, indent=2))


def chunk_bounds(size, multi=1):
    KiB, MiB = 1024, 1024 * 1024
    starts = [0, 128, 384, 768, 1280, 1920, 2688]
    i = 1
    while True:
        if i <= 7:
            off, ln = starts[i - 1] * KiB, i * 128 * KiB
        else:
            off, ln = 3584 * KiB + (i - 8) * MiB * multi, MiB * multi
        if off >= size and not (size == 0 and i == 1):
            return
        yield off, min(ln, size - off)
        i += 1


def meta_mac(data, aes_key, nonce):
    enc = lambda k, b: aes_ecb_enc(k, b)
    file_mac = bytes(16)
    for off, ln in chunk_bounds(len(data)):
        cm = nonce + nonce
        chunk = data[off:off + ln]
        for j in range(0, len(chunk), 16):
            blk = chunk[j:j + 16].ljust(16, b"\0")
            cm = enc(aes_key, bytes(a ^ b for a, b in zip(cm, blk)))
        file_mac = enc(aes_key, bytes(a ^ b for a, b in zip(file_mac, cm)))
    w = str_to_a32(file_mac)
    return a32_to_bytes([w[0] ^ w[1], w[2] ^ w[3]])


mac_data = bytes((i * 31 + 7) % 256 for i in range(5 * 1024 * 1024 + 123))
print(json.dumps({
    "mac_data_len": len(mac_data),
    "mac_aes_key_hex": aes_key.hex(),
    "mac_nonce_hex": nonce.hex(),
    "mac_meta_mac_hex": meta_mac(mac_data, aes_key, nonce).hex(),
    "mac_small_meta_mac_hex": meta_mac(b"hello world", aes_key, nonce).hex(),
    "mac_empty_meta_mac_hex": meta_mac(b"", aes_key, nonce).hex(),
}, indent=2))


def hashcash(easiness, token_b64):
    import hashlib
    token = base64.urlsafe_b64decode(token_b64 + "=" * (-len(token_b64) % 4))
    threshold = (((easiness & 63) << 1) + 1) << (((easiness >> 6) & 3) * 7 + 3)
    body = token * 262144
    for nonce in range(1 << 32):
        prefix = struct.pack(">I", nonce)
        digest = hashlib.sha256(prefix + body).digest()
        if struct.unpack(">I", digest[:4])[0] <= threshold:
            return "1:%s:%s" % (token_b64, b64url(prefix))


hc_token = b64url(bytes(range(100, 148)))
print(json.dumps({
    "hashcash_challenge": "1:192:1700000000:" + hc_token,
    "hashcash_solution": hashcash(192, hc_token),
}, indent=2))


def mpi(n):
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return struct.pack(">H", n.bit_length()) + raw


def login_fixture():
    """A v2 account login reply (`us0` + `us`) with a real RSA key."""
    import os
    from cryptography.hazmat.primitives.asymmetric import rsa

    password = "correct horse battery staple"
    salt = bytes(range(32))
    kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=32, salt=salt, iterations=100000)
    derived = kdf.derive(password.encode())
    password_aes = derived[:16]
    master = bytes(range(0xA0, 0xB0))

    priv = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    nums = priv.private_numbers()
    p, q, d = nums.p, nums.q, nums.d
    u = pow(p, -1, q)
    privk = mpi(p) + mpi(q) + mpi(d) + mpi(u)
    privk += b"\0" * ((16 - len(privk) % 16) % 16)

    # Realistic layout: the plaintext fills the modulus minus one byte, so
    # the fixed-length RSA output is `00 || sid || random`.
    modulus_len = ((p * q).bit_length() + 7) // 8
    sid_raw = b"\x01" + os.urandom(42)
    m = int.from_bytes(sid_raw + os.urandom(modulus_len - 1 - 43), "big")
    csid = pow(m, 65537, p * q)
    return {
        "login_email": "User@Example.com",
        "login_password": password,
        "login_salt_b64url": b64url(salt),
        "login_k": b64url(aes_ecb_enc(password_aes, master)),
        "login_privk": b64url(aes_ecb_enc(master, privk)),
        "login_csid": b64url(mpi(csid)),
        "login_master_hex": master.hex(),
        "login_expected_sid": b64url(sid_raw),
        "login_user_hash": b64url(derived[16:]),
    }


print(json.dumps(login_fixture(), indent=2))
