import random
import string
import argparse
import logging

from dsa_sha3 import sha3_224, sha3_256, sha3_384, sha3_512

def get_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-f', '--file', type=str,
                        default="../data/file1.txt",
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

def main():
    fmt = '[%(levelname)s] %(asctime)s - %(message)s'
    logging.basicConfig(level=logging.INFO, format=fmt)

    try:
        args = get_args()
    except Exception as ex:
        logging.error(ex)
        logging.error('Missing or invalid argument(s).')

    x = ''
    for _ in range(300):
        x = x + random.choice(string.ascii_letters)
    logging.info(f"testing for: {x}")
    hashed = sha3_512(x).hexdigest()
    logging.info(f"Digest: {hashed}")

if __name__ == '__main__':
    main()

