import cmd
import logging
import os
import sys

from SHA3 import sha3_224, sha3_256, sha3_384, sha3_512
from RSA import RSAKey, RSA
import prime
from utils import *

SHA_VER = {'224': sha3_224,
           '256': sha3_256,
           '384': sha3_384,
           '512': sha3_512}

class InteractiveShell(cmd.Cmd):
    intro = '\n  type `help` or `?` to see usage\n  type `exit` or `q` to exit\n'
    prompt = 'DSA >> '

    def __init__(self):
        cmd.Cmd.__init__(self)

        self.config = {
            "e": '65537',
            "sha": '512'
        }

        sha = SHA_VER[self.config["sha"]]
        self.set_sha(sha)
        key = RSAKey(bits=1024, e=int(self.config['e']))
        print('Default key generated (1024 bits)')
        self.set_key(key)
        self.last = None

    def set_sha(self, sha):
        self.sha = sha

    def set_key(self, key):
        self.key = key
        self.rsa = RSA(key)
        key.dump()

    def do_q(self, line):
        """
        quit
        """
        print('Bye.')
        return True

    def do_exit(self, line):
        """
        quit
        """
        print('Bye.')
        return True

    def do_EOF(self, line):
        """
        quit
        """
        print('Bye.')
        return True

    def do_set(self, line):
        """
        set key val

        available key:
            e   public exponent
        """

        try:
            key, val = line.split()
        except ValueError:
            print('error while parsing arguments')
            return

        if not key:
            print('key can not be empty')
            return
        self.config[key] = val

    def do_get(self, key):
        """
        get key

        available key:
            e   public exponent
        """

        if not key:
            print('key can not be empty')
            return

        print('%s: %r' % (key, self.config.get(key, None)))

    def complete_sign(self, *args):
        return self.complete_filename(*args)

    def do_sign(self, file):
        """
        sign [file]

        keep file empty to read data from stdin
        """

        if self.config['key_state'] == 'public':
            print('FAILED: Signing requires private key!')
            print('Current key state is public.')
            return

        sha = self.sha()

        if not file:
            data = input('Data input to sign:')
            data = data.encode('ascii')
            sha.update(data)
        else:
            try:
                with open(file, "rb") as f:
                    # Read and update hash string value in blocks of 4K
                    for byte_block in iter(lambda: f.read(4096), b""):
                        sha.update(byte_block)
            except:
                print('Can not open file %r' % file)
                return

        digest = sha.hexdigest()
        print('Digest: %s' % digest)
        signature = self.rsa.sign_data(digest.encode('ascii'))
        self.last = signature
        print('Signature: %s' % signature)

    def complete_verify(self, *args):
        return self.complete_filename(*args)

    def do_verify(self, file):
        """
        verify [file]

        keep file empty to read data from stdin
        """

        sha = self.sha()

        if not file:
            try:
                data = input('Data input to verify: ')
                data = data.encode('ascii')
                sha.update(data)
            except:
                print('Error when input data to verify')
        else:
            try:
                with open(file, "rb") as f:
                    # Read and update hash string value in blocks of 4K
                    for byte_block in iter(lambda: f.read(4096), b""):
                        sha.update(byte_block)
            except:
                print('Can not open file %r' % file)
                return

        fsignature = input(f'Signature file to verify {file}: ')
        # keep stdin empty to manually input signature in hex
        if fsignature == '':
            signature = input('Signature to verify in hex: ')
            try:
                signature = unhex(signature)
            except:
                print('Read input error')
                return
        else:
            try:
                with open(fsignature, "rb") as f:
                    signature = f.read()
                print('Signature: %s' % signature)
            except:
                print('Can not open file %r' % fsignature)
                return

        digest = sha.hexdigest()
        print('Digest: %s' % digest)

        self.rsa.verify_data(signature, digest.encode('ascii'))

    def do_keygen(self, bits):
        """
        keygen [bits=1024]
        """
        if not bits: bits = 1024

        try:
            bits = int(bits)
        except:
            print('Invalid number')
            return

        if bits > 2048:
            print('You are generating long RSA keypair, it may take some while.')
            print('Interrupt by Ctrl-C')

        try:
            key = RSAKey(bits=bits, e=int(self.config['e']))
            self.set_key(key)
            self.config['key_state'] = 'private'
        except ValueError:
            print('Can not generate key')
        except KeyboardInterrupt:
            print('Canceld')

    def do_simplify(self, line):
        """
        simplify

        strip unnecessary fields of RSAKey.
            (this operation will disable CRT decryption optimize)
        """

        self.set_key(self.key.simplify())

    def do_prime(self, bits):
        """
        prime bits

        generate a prime with n-bits length
        """

        print(prime.randprime_bits(int(bits)))

    def do_dump(self, file):
        """
        dump [file]

        print last result or save last reuslt to file
        """

        if not self.last:
            print('Nothing in last result')
            return

        if file:
            try:
                open(file, 'wb').write(self.last)
            except:
                print('Can not save file')
        else:
            print(enhex(self.last) if type(self.last) is Bytes else self.last)

    def do_dumpstr(self, line):
        """
        dumpstr

        print last result as string
        """

        if not self.last:
            print('Nothing in last result')
            return
        else:
            print(repr(self.last))

    def complete_loadkey(self, *args):
        return self.complete_filename(*args)

    def do_loadkey(self, file):
        """
        loadfullkey [fullkey_file]

        read key from file or read JSON-format key from stdin
        """

        if file:
            try:
                json_data = open(file, 'rb').read()
            except:
                print('Can not read file')
                return
        else:
            json_data = input('Input JSON-format key:')

        try:
            key = RSAKey.from_json(json_data)
        except Exception as e:
            print('Can not load key, Error show below:')
            print(e)
            return

        self.set_key(key)
        self.config['key_state'] = 'private'
        print('Key loaded')

    def complete_loadprivatekey(self, *args):
        return self.complete_filename(*args)

    def do_loadprivatekey(self, file):
        """
        loadkey [privatekey_file]

        read key from file
        """

        try:
            private_key_dict = load_key_dict(file)
            private_key = RSAKey(**private_key_dict)
            self.set_key(private_key)
            self.config['key_state'] = 'private'
            print('Private Key loaded')
        except:
            print('Cannot load or load private key.')
            return

    def complete_loadpublickey(self, *args):
        return self.complete_filename(*args)

    def do_loadpublickey(self, file):
        """
        loadkey [publickey_file]

        read key from file
        """

        try:
            public_key_dict = load_key_dict(file)
            public_key = RSAKey(**public_key_dict)
            self.set_key(public_key)
            self.config['key_state'] = 'public'
            print('Public Key loaded')
        except:
            print('Cannot load or load public key.')
            return

    def complete_filename(self, text, line, begidx, endidx):
        arg = line.split()[1:]

        if not arg:
            completions = os.listdir('./')
        else:
            dirname, part, base = arg[-1].rpartition('/')
            if part == '':
                dirname = './'
            elif dirname == '':
                dirname = '/'

            completions = []
            for f in os.listdir(dirname):
                if f.startswith(base):
                    if os.path.isfile(os.path.join(dirname,f)):
                        completions.append(f)
                    else:
                        completions.append(f+'/')

        return completions

    def do_dumpkey(self, file):
        """
        dumpkey [file]

        dump key to file or stdout
        """

        if file:
            try:
                if self.config['key_state'] == 'private':
                    self.key.private_to_json_file(file)
                elif self.config['key_state'] == 'public':
                    self.key.public_to_json_file(file)
                print('Key dumped to file %s' % file)
            except:
                print('Can not dump key to file')
        else:
            print(f'Key state: {self.config["key_state"]}')
            print(self.rsa.key.as_dict())
            self.key.dump()

if __name__ == '__main__':
    fmt = '[%(levelname)s] %(asctime)s - %(message)s'
    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format=fmt)
    InteractiveShell().cmdloop()
