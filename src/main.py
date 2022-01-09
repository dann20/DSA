import sys
import argparse
import logging

from .sha3 import sha3_224, sha3_256, sha3_384, sha3_512
from .rsa import RSAKey, RSA

def get_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-f', '--file', type=str,
                        default="../data/1.md",
                        help='input file for digital signing or verification')
    parser.add_argument('--private', type=str,
                        default="tmp",
                        help='private key file')
    parser.add_argument('--public', type=str,
                        default="tmp",
                        help='public key file')
    parser.add_argument('-s', '--sign',
                        action='store_true',
                        help='performs signing, requires input file and private key')
    parser.add_argument('-v', '--verify',
                        action='store_true',
                        help='performs verification, requires input file and public key')
    parser.add_argument('-g', '--generate',
                        action='store_true',
                        help='generates new public-private key pair')
    args = parser.parse_args()
    return args

def main():
    fmt = '[%(levelname)s] %(asctime)s - %(message)s'
    logging.basicConfig(level=logging.INFO, format=fmt)

    try:
        args = get_args()
    except Exception as ex:
        logging.error(ex)
        logging.error('Missing or invalid argument(s).')
        sys.exit(1)

    sha = sha3_512()
    with open(args.file, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha.update(byte_block)
    digest = sha.hexdigest()
    logging.info('Digest: %s' % digest)

    rsa = RSA(bits=2048)
    logging.info('Key:')
    rsa.key.dump()

    signature = rsa.sign_data(digest.encode('ascii'))
    logging.info('Signature:  %s' % signature)

    rsa.verify_data(signature, digest.encode('ascii'))

if __name__ == '__main__':
    main()
