import struct
from Crypto.Cipher import AES

def _xor(s1, s2):
    return bytes(a ^ b for a, b in zip(s1, s2))

# from https://github.com/ihaveamac/switchfs
# switchfs is under the MIT license
# taken from @plutooo's crypto gist (https://gist.github.com/plutooo/fd4b22e7f533e780c1759057095d7896),
class XTSN:
    def __init__(self, crypt: bytes, tweak: bytes):
        self.crypt = crypt
        self.tweak = tweak

        self.c_enc = AES.new(self.tweak, AES.MODE_ECB).encrypt
        self.c_dec = AES.new(self.crypt, AES.MODE_ECB).decrypt

    def decrypt(self, buf: bytes, sector_off: int, sector_size: int = 0x200) -> bytes:
        out = bytearray()

        p = struct.Struct('>QQ')

        for i in range(len(buf) // sector_size):
            pos = sector_off + i
            tweak = self.c_enc(p.pack(0, pos))

            for j in range(sector_size // 16):
                off = i * sector_size + j * 16

                blk = _xor(self.c_dec(_xor(buf[off:off + 16], tweak)), tweak)

                tweak = int.from_bytes(tweak, 'little')
                if tweak & (1 << 127):
                    tweak = ((tweak & ~(1 << 127)) << 1) ^ 0x87
                else:
                    tweak <<= 1
                tweak = tweak.to_bytes(16, 'little')

                out.extend(blk)

        return bytes(out)

    decrypt_long = decrypt

    def encrypt(self, buf: bytes, sector_off: int, sector_size: int = 0x200) -> bytes:
        out = bytearray()

        p = struct.Struct('>QQ')

        for i in range(len(buf) // sector_size):
            pos = sector_off + i
            tweak = self.c_enc(p.pack(0, pos))

            for j in range(sector_size // 16):
                off = i * sector_size + j * 16

                blk = _xor(self.c_enc(_xor(buf[off:off + 16], tweak)), tweak)

                tweak = int.from_bytes(tweak, 'little')
                if tweak & (1 << 127):
                    tweak = ((tweak & ~(1 << 127)) << 1) ^ 0x87
                else:
                    tweak <<= 1
                tweak = tweak.to_bytes(16, 'little')

                out.extend(blk)

        return bytes(out)
