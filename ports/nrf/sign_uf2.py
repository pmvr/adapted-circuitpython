#!/usr/bin/env python3
import sys
import os
import argparse
import struct
from hashlib import sha256
from binascii import b2a_hex

UF2_MAGIC_START0 = b'\x55\x46\x32\x0a'  # "UF2\n"
UF2_MAGIC_START1 = b'\x57\x51\x5d\x9e'  # Randomly selected
UF2_MAGIC_END    = b'\x30\x6f\xb1\x0a'  # Ditto



def rsa_sign(hash256, sk, modulus):
    while True:
        h = int.from_bytes(os.urandom(256-32) + hash256, 'big')
        if h < modulus:
            break
    sig = pow(h, sk, modulus)
    if pow(sig, 3, modulus).to_bytes(256, 'big')[-32:] != hash256:
        raise ValueError('RSA verifycation failed.')
    return sig.to_bytes(256, 'big')


def h256(data):
    s = sha256()
    s.update(data)
    return s.digest()


def sign_uf2(buf, output, rsa_d, rsa_m):
    hash_value = bytes(32)
    numblocks = len(buf) // 512
    for blockno in range(numblocks):
        ptr = blockno * 512
        block = buf[ptr:ptr + 512]
        magicStart0 = block[0*4 : 1*4]
        magicStart1 = block[1*4 : 2*4]
        magicEnd = block[-4:]
        if magicStart0 != UF2_MAGIC_START0 or magicStart1 != UF2_MAGIC_START1 or magicEnd != UF2_MAGIC_END:
            assert False, b"Bad magic: %s %s %s" % (b2a_hex(magicStart0), b2a_hex(magicStart1), b2a_hex(magicEnd))
        if block[8] & 1:
            print(f"NO-flash flag set; skip block {blockno}")
            continue
        if blockno != struct.unpack(b"<I", block[5*4: 6*4])[0]:
            assert False, "mismatch of block numbers" 
        datalen = struct.unpack(b"<I", block[4*4: 4*5])[0]
        if datalen > 256:
            assert False, f"Invalid UF2 data size of {datalen} at " + ptr
        addr = struct.unpack(b"<I", block[3*4 : 4*4])[0]
        if addr & 0xff > 0:
            assert False, "Wrong address %x" % addr
        if addr < 0x26000:  # USER_FLASH_START
            assert False, "address too low %x" % addr
        if addr + datalen > 0xAD000:  # USER_FLASH_END
            assert False, "address too high %x" % addr
        hash_value = bytes((a ^ b for a,b in zip(hash_value, h256(block[: 32+256]))))
    print('hash', b2a_hex(hash_value))
    if output is not None:
        sig = rsa_sign(hash_value, rsa_d, rsa_m)
        print ('sig =', b2a_hex(sig))
        lastblock2 = buf[-1024:-512]
        lastblock2 = lastblock2[:32+256] + sig[:128] + lastblock2[32+256+128:]
        lastblock1 = buf[-512:]
        lastblock1 = lastblock1[:32+256] + sig[128:] + lastblock1[32+256+128:]
        # lastblock = lastblock[:32+256] + signature + lastblock[32+256+64:]
        # lastblock = lastblock[:32+256] + hash_value + lastblock[32+256+32:]
        with open(output, 'wb') as fout:
            fout.write(buf[:-1024])
            fout.write(lastblock2)
            fout.write(lastblock1)


def error(msg):
    print(msg)
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='Sign UF2')
    parser.add_argument('input', metavar='INPUT', type=str, nargs='?',
                        help='input file UF2')
    parser.add_argument('-o' , '--output', metavar="FILE", dest='output', type=str, default=None,
                        help='write output to named file')
    parser.add_argument('-r' , '--rsa-parameter', metavar="FILE", dest='rsa_fn', type=str, default=None,
                        help='input of RSA parameter in hex format first line modulus second line signing/secret key')
    args = parser.parse_args()
 
    if not args.input:
        error("Need input file")
    with open(args.input, mode='rb') as f:
        inpbuf = f.read()
    with open(args.rsa_fn, mode='r') as f:
        # first line modulus, second line signing/secret key
        rsa_m, rsa_d = [int(x, 16) for x in f.read().split('\n')]

    sign_uf2(inpbuf, args.output, rsa_d, rsa_m)
    
    
if __name__ == "__main__":
    main()
