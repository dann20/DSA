import sys
import argparse
import logging

from mode import sign, verify, generate_keys

FUNCTIONS = {'sign': sign,
            'verify': verify,
            'generate': generate_keys}

class MyParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write('error: %s\n' % message)
        self.print_help()
        sys.exit(2)

def get_args():
    parser = MyParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('command', type=str,
                        choices=FUNCTIONS.keys(),
                        default='generate',
                        help='chooses mode: sign, verify or generate (default)\n \
                        - sign: performs signing, requires input file and private key \n \
                        if private key is not provided, generates new key pair \n \
                        - verify: performs verification, requires input file, signature and public key \n \
                        - generate: generates new public-private RSA key pair')
    parser.add_argument('-f', '--file', type=str,
                        default="../data/1.md",
                        help='input file for digital signing or verification')
    parser.add_argument('-s', '--signature', '--sig', type=str,
                        default="../data/1.md.sig",
                        help='signature of input file for verification')
    parser.add_argument('--private', type=str,
                        help='private key file')
    parser.add_argument('--public', type=str,
                        help='public key file')
    parser.add_argument('--sha', type=int,
                        default=512,
                        const=512,
                        nargs='?',
                        choices=[224, 256, 384, 512],
                        help='chooses version of SHA3 (default: SHA3-512)')
    parser.add_argument('--rsa-key-size', type=int,
                        default=2048,
                        help='sets RSA key size (default: 2048 bits)')
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    fmt = '[%(levelname)s] %(asctime)s - %(message)s'
    logging.basicConfig(level=logging.INFO, format=fmt)

    try:
        args = get_args()
    except Exception as ex:
        logging.error(ex)
        logging.error('Missing or invalid argument(s).')
        sys.exit(1)

    func = FUNCTIONS[args.command]
    func(args)
