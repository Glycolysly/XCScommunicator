import base64

# --- RC4 加密解密 ---
def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    out = bytearray()
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

RC4_KEY = b'supersecretkey'

CUSTOM_ALPHABET = "idhR+nWSPOU0CGIrNmAqVZlYuo2sDt7yg6MBXF1aw4Kv9LHJkjb5p8/zxcefQ3ET"
STANDARD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

ENCODE_TRANS = str.maketrans(STANDARD_ALPHABET, CUSTOM_ALPHABET)
DECODE_TRANS = str.maketrans(CUSTOM_ALPHABET, STANDARD_ALPHABET)

def custom_b64encode(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    standard = base64.b64encode(data).decode('utf-8')
    return standard.translate(ENCODE_TRANS)

def custom_b64decode(data, binary=False):
    standard = data.translate(DECODE_TRANS)
    raw = base64.b64decode(standard)
    if binary:
        return raw
    else:
        return raw.decode('utf-8')

def enc(data):
    return custom_b64encode(data)

def dec(data, binary=False):
    return custom_b64decode(data, binary=binary)
