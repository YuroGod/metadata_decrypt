import struct
import argparse

def calculate_crc(data: bytes, offset: int, size: int) -> int:
    kPoly = 0x9823D6E
    value = 0xFFFFFFFF

    crc_table = [0] * 256
    for i in range(256):
        r = i
        for _ in range(8):
            if (r & 1) != 0:
                r ^= kPoly
            r >>= 1
        crc_table[i] = r

    for i in range(size):
        value = (crc_table[(value ^ data[offset + i]) & 0xFF] ^ (value >> 8)) + 0x10

    return (~value - 0x7D29C488) & 0xFFFFFFFF

def rc4(data: bytearray, key: int):
    key = key.to_bytes(4, byteorder='little')
    
    S = list(range(256))
    T = [0] * 256

    if len(key) == 256:
        T = list(key)
    else:
        for i in range(256):
            T[i] = key[i % len(key)]

    j = 0
    for i in range(256):
        j = (j + S[i] + T[i]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    for p in range(len(data)):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        k = (K << 6) | (K >> 2)
        data[p] ^= (k + 0x3A) & 0xFF

def b2i(data: bytearray, offset: int):
    """Convert bytes to integer."""
    return struct.unpack_from('<I', data, offset)[0]

def b2d(lst: bytearray):
    """Convert bytes to a list of DWORDs."""
    dword_list = []
    for i in range(0, 128, 4):
        dword = struct.unpack('<I', lst[i:i+4])[0]
        dword_list.append(dword)

    return dword_list

def decrypt(input_path, output_path):
    with open(input_path, "rb") as fp:
        data = bytearray(fp.read()[8:])

    dec_data = bytearray.fromhex("AF 1B B1 FA 1D 00 00 00")

    seed_bytes = struct.pack('1i', len(data))
    seed = calculate_crc(seed_bytes, 0, len(seed_bytes))
    key = seed ^ b2i(data, 24)
    keyBlock = data[:128]
    head_128_bytes = data[:128]

    rc4(keyBlock, key)
    rc4(head_128_bytes, seed)
    dec_data += head_128_bytes

    keyBlockB = keyBlock
    keyBlock = b2d(keyBlock)

    short_key = [0] * 4
    short_key[0] = seed ^ (b2i(data, 32) + 0x8195E)
    short_key[1] = key ^ (b2i(data, 76) + 0x75568)
    short_key[2] = seed ^ (keyBlock[11] + 0x3482A5)
    short_key[3] = key ^ (keyBlock[15] + 0xA7498D)

    long_key = [0] * 9
    long_key[0] = keyBlock[3] ^ 0x3914F13
    long_key[1] = short_key[3] ^ 0x34E00E
    long_key[2] = long_key[0] ^ keyBlock[7]
    long_key[7] = short_key[2] ^ long_key[1]
    long_key[3] = long_key[7] ^ keyBlock[8]
    long_key[5] = short_key[1] ^ 0x836E4C
    long_key[4] = short_key[0] ^ long_key[5]
    long_key[6] = b2i(data, 16) ^ 0x31BB9B1
    long_key[8] = b2i(data, 24) ^ short_key[0] ^ long_key[5]

    data_block = data[128:]
    block_count = len(data_block) // 0x80
    for i in range(block_count):
        block_offset = i * 128
        dec_type = long_key[i % len(long_key)] % len(short_key)
        block = 0
        for j in range(0x20):
            if dec_type == 0:
                block = b2i(data, 128 + block_offset + j * 4) ^ keyBlock[j] ^ short_key[keyBlock[j % len(keyBlock)] % len(short_key)] ^ j
            elif dec_type == 1:
                block = b2i(data, 128 + block_offset + j * 4) ^ keyBlock[j] ^ short_key[long_key[j % len(long_key)] % len(short_key)] ^ j
            elif dec_type == 2:
                block = b2i(data, 128 + block_offset + j * 4) ^ keyBlock[j] ^ long_key[j % len(long_key)] ^ (32 - j)
            elif dec_type == 3:
                block = b2i(data, 128 + block_offset + j * 4) ^ keyBlock[j] ^ short_key[keyBlock[j % len(keyBlock)] % len(short_key)]
            dec_data += block.to_bytes(4, byteorder='little')

    if len(data_block) % 128 > 0:
        for i in range(len(data_block) % 128):
            b = (data[128 + block_offset + 128 + i] ^ (keyBlockB[i] ^ (long_key[(short_key[i % len(short_key)]) % len(long_key)] % 0xFF) ^ i)) & 0xff
            dec_data += b.to_bytes()
            

    with open(output_path, "wb+") as fp:
        fp.write(dec_data)


def main():
    parser = argparse.ArgumentParser(description="Decrypting the global-metadata.dat file encrypted by NEP2")
    parser.add_argument("input_path", type=str, help="Path to the input global-metadata.dat file.")
    parser.add_argument("output_path", type=str, help="Path to save the decrypted file.")
    args = parser.parse_args()
    
    decrypt(args.input_path, args.output_path)
    
if __name__ == "__main__":
    main()

