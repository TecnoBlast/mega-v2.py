import base64
import struct
import hashlib

def solve_hashcash(header_value):
    parts = header_value.split(':')
    if len(parts) != 4:
        return None
    try:
        easiness = int(parts[1])
    except ValueError:
        return None
    token = parts[3]
    threshold = ((easiness & 63) << 1) + 1 << (easiness >> 6) * 7 + 3
    padded_token = token + '=' * (-len(token) % 4)
    try:
        token_bytes = base64.urlsafe_b64decode(padded_token)
    except Exception:
        return None
    pad_len = len(token_bytes) % 16
    if pad_len != 0:
        token_bytes += b'\x00' * (16 - pad_len)
    num_replications = 262144
    token_slot_size = 48
    buffer_size = 4 + num_replications * token_slot_size
    buffer = bytearray(buffer_size)
    for i in range(num_replications):
        offset = 4 + i * token_slot_size
        buffer[offset:offset + len(token_bytes)] = token_bytes
    for _ in range(4294967295):
        for j in range(4):
            buffer[j] = buffer[j] + 1 & 255
            if buffer[j] != 0:
                break
            if j == 3:
                return None
        h = hashlib.sha256(buffer).digest()
        hash_val = struct.unpack('>I', h[:4])[0]
        if hash_val <= threshold:
            cash_value = base64.urlsafe_b64encode(buffer[:4]).rstrip(b'=').decode('utf-8')
            return f'1:{token}:{cash_value}'
    return None