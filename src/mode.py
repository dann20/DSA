import sys
import logging

from SHA3 import sha3_224, sha3_256, sha3_384, sha3_512
from RSA import RSAKey, RSA

SHA_VER = {224: sha3_224,
           256: sha3_256,
           384: sha3_384,
           512: sha3_512}

def sign(args):
    if not args.private:
        args.public, args.private = generate_keys(args)
    sha = SHA_VER[args.sha]()

    if not args.file:
        logging.error('No input file.')
        sys.exit(1)

    logging.info('Filename: %s' % args.file)
    with open(args.file, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha.update(byte_block)

    digest = sha.hexdigest()
    logging.info('Digest: %s' % digest)

    private_key = RSAKey.from_json_file(args.private)
    rsa = RSA(key=private_key)
    logging.info('Used private key: %s' % args.private)
    rsa.key.dump()

    signature = rsa.sign_data(digest.encode('ascii'))
    logging.info('Signature:  %s' % signature)

    with open(f'{args.file}.sig', 'wb') as f:
        f.write(signature)

def verify(args):
    if not args.file:
        logging.error('No input file.')
        sys.exit(1)
    elif not args.signature:
        logging.error('No signature of input file.')
        sys.exit(1)
    elif not args.public:
        logging.error('No public key specified.')
        sys.exit(1)

    sha = SHA_VER[args.sha]()

    logging.info('Filename: %s' % args.file)
    with open(args.file, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha.update(byte_block)

    digest = sha.hexdigest()
    logging.info('Digest: %s' % digest)

    logging.info('Signature filename: %s' % args.signature)
    with open(args.signature, "rb") as f:
        signature = f.read()
    logging.info('Signature: %s' % signature)

    public_key = RSAKey.from_json_file(args.public)
    rsa = RSA(key=public_key)
    logging.info('Used public key: %s' % args.public)
    rsa.key.dump()

    rsa.verify_data(signature, digest.encode('ascii'))

def generate_keys(args):
    rsa = RSA(bits=args.rsa_key_size)
    logging.info('GENERATED KEYS:')
    rsa.key.dump()
    rsa.key.private_to_json_file()
    rsa.key.public_to_json_file()
    return '../keys/publickey.json', '../keys/privatekey.json'
