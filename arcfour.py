from functools import cache

@cache
def bytes_to_int(b: bytes) -> int:
    int_value = 0
    for i in range(len(b)):
        int_value = int_value * 256 + int(b[i])
    return int_value


@cache
def int_to_bytes(number: int) -> bytes:
    num_bytes = (number.bit_length() + 7) // 8
    little_endian_bytes = bytearray(num_bytes)
    for i in range(num_bytes):
        little_endian_bytes[i] = (number >> (8 * i)) & 0xFF
    return bytes(little_endian_bytes)[::-1]


class Arcfour:
    def __init__(self) -> None:
        pass

    def ksg(self, key: bytes):
        s = list(range(256))

        j = 0
        for i in range(256):
            j = (j + s[i] + key[i % len(key)]) % 256
            s[i], s[j] = s[j], s[i]

        i = 0
        j = 0
        while True:
            i = (i + 1) % 256
            j = (j + s[i]) % 256
            s[i], s[j] = s[j], s[i]
            k = s[(s[i] + s[j]) % 256]
            yield k

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        ks = self.ksg(key)
        return b''.join(bytes([next(ks) ^ byte]) for byte in data)

    def decrypt(self, data: bytes, key: bytes) -> bytes:
        ks = self.ksg(key)
        return b''.join(bytes([next(ks) ^ byte]) for byte in data)


ARC4 = Arcfour()
