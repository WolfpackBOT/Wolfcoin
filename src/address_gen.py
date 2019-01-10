# pip install base58 / ecdsa
# tested in python 3.6.5

import os, binascii, hashlib, base58, ecdsa

def ripemd160(x):
    d = hashlib.new('ripemd160')
    d.update(x)
    return d

for n in range(1):   # number of key pairs to generate`

    # generate private key, uncompressed bitcoin WIF starts with "5"
    priv_key = os.urandom(32)
    fullkey = 'c1' + binascii.hexlify(priv_key).decode()
    sha256a = hashlib.sha256(binascii.unhexlify(fullkey)).hexdigest()
    sha256b = hashlib.sha256(binascii.unhexlify(sha256a)).hexdigest()
    WIF = base58.b58encode(binascii.unhexlify(fullkey+sha256b[:8]))

    # get public key, uncompressed bitcoin address starts with "1"
    sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    publ_key = '04' + binascii.hexlify(vk.to_string()).decode()
    hash160 = ripemd160(hashlib.sha256(binascii.unhexlify(publ_key)).digest()).digest()
    publ_addr_a = b"\x41" + hash160
    checksum = hashlib.sha256(hashlib.sha256(publ_addr_a).digest()).digest()[:4]
    publ_addr_b = base58.b58encode(publ_addr_a + checksum)
    i = n + 1
    print('Private Key     : ' + WIF.decode())
    print('Wolfcoin Address : ' + publ_addr_b.decode())
