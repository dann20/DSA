import os
import logging
import textwrap
from dataclasses import dataclass, field
from typing import Protocol

from SHA3 import sha3_224, sha3_256, sha3_384, sha3_512, Keccak
from RSA import RSAKey, RSA

from PyQt5.QtCore import QThread, pyqtSignal

SHA_VER = {
    "SHA3-224": sha3_224,
    "SHA3-256": sha3_256,
    "SHA3-384": sha3_384,
    "SHA3-512": sha3_512,
}
KEYS = ["N", "e", "d", "p", "q", "dp", "dq", "qinv"]


class SHACallable(Protocol):
    """
    Custom Callable used for type hinting with SHA3 functions.
    """
    def __call__(self, data: bytes | None = None) -> Keccak:
        ...


@dataclass(slots=True)
class DSA:
    config: dict = field(
        default_factory=lambda: {
            "e": "19853061807268348331",
            "sha": "SHA3-512",
            "key_size": "2048",
        }
    )
    filename: None | str = ""
    input_string: None | str = ""
    signature_filename: None | str = ""
    sha: SHACallable = SHA_VER["SHA3-512"]
    signature: None | bytes = None
    key: None | RSAKey = None
    rsa: None | RSA = None

    def set_key(self, key: RSAKey):
        self.key = key
        self.rsa = RSA(key)

    def set_sha(self, sha: str):
        self.sha = SHA_VER[sha]

    def set_value_config(self, key: str, value: str):
        self.config[key] = value

    def log_key(self):
        def pref_generator(headline):
            yield headline
            prefspc = " " * len(headline)
            while True:
                yield prefspc

        def dump_attr(attrname, indent=0):
            val = getattr(self.key, attrname, None)
            if not val:
                return " " * indent + "%4s = None\n" % attrname
            else:
                headline = "\n" + " " * indent + "%4s = " % attrname
                return "\n".join(
                    p + i
                    for p, i in zip(
                        pref_generator(headline), textwrap.wrap("0x%x," % val)
                    )
                )

        log = ""
        for attr in KEYS:
            log += dump_attr(attr)
        log += "\n"
        return log


class KeygenWorker(QThread):
    signal_keygen_dsa = pyqtSignal(DSA)
    signal_keygen_status = pyqtSignal(bool)

    def __init__(self, dsa: DSA):
        super().__init__()
        self.dsa = dsa

    def run(self):
        try:
            bits = self.dsa.config["key_size"]
            e = self.dsa.config["e"]
            key = RSAKey(bits=int(bits), e=int(e))
            self.dsa.set_key(key)
            self.dsa.config["key_state"] = "private"
            logging.info("Key generated")
            logging.info(self.dsa.log_key())
            self.signal_keygen_dsa.emit(self.dsa)
            self.signal_keygen_status.emit(True)
        except Exception as Ex:
            logging.error(Ex)
            self.signal_keygen_status.emit(False)


class SignWorker(QThread):
    signal_sign_dsa = pyqtSignal(DSA)
    signal_sign_text = pyqtSignal(str)
    signal_sign_status = pyqtSignal(bool)

    def __init__(self, dsa: DSA):
        super().__init__()
        self.dsa = dsa

    def run(self):
        sha = self.dsa.sha()
        log = ""

        # only filename or input_string is set at a time
        if self.dsa.filename:
            try:
                log += "Signing file %s\n" % self.dsa.filename
                with open(self.dsa.filename, "rb") as f:
                    # Read and update hash string value in blocks of 4K
                    for byte_block in iter(lambda: f.read(4096), b""):
                        sha.update(byte_block)
                filename, input_string = self.dsa.filename, None
            except Exception as ex:
                logging.error(ex)
                logging.error("Can not open file %r" % self.dsa.filename)
                self.signal_sign_status.emit(False)

        elif self.dsa.input_string:
            log += "Signing message: %s\n" % self.dsa.input_string
            self.dsa.filename = os.path.join(os.getcwd(), "../data/message.txt")
            with open(self.dsa.filename, "w") as f:
                f.write(self.dsa.input_string)
                log += 'Saved message to "message.txt"\n'
            sha.update(self.dsa.input_string.encode("ascii"))
            filename, input_string = None, self.dsa.input_string

        else:
            logging.error("No input string or file provided")
            self.signal_sign_status.emit(False)

        digest = sha.hexdigest()
        log += "Digest: %s\n" % digest
        signature = self.dsa.rsa.sign_data(digest.encode("ascii"))
        log += "Signature: %s\n" % signature
        with open(f"{self.dsa.filename}.sig", "wb") as f:
            f.write(signature)
            log += f"Saved signature to file {self.dsa.filename}.sig\n\n"
        self.dsa.filename, self.dsa.input_string = filename, input_string
        logging.info(log)
        self.signal_sign_dsa.emit(self.dsa)
        self.signal_sign_text.emit(log)
        self.signal_sign_status.emit(True)


class VerifyWorker(QThread):
    signal_verify_dsa = pyqtSignal(DSA)
    signal_verify_text = pyqtSignal(str)
    signal_verify_status = pyqtSignal(bool)

    def __init__(self, dsa: DSA):
        super().__init__()
        self.dsa = dsa

    def run(self):
        sha = self.dsa.sha()
        log = ""

        if (
            not self.dsa.filename and not self.dsa.input_string
        ) or not self.dsa.signature:
            self.signal_verify_status.emit(False)

        # only filename or input_string is set at a time
        elif self.dsa.filename:
            try:
                log += "Verifying file %s\n" % self.dsa.filename
                with open(self.dsa.filename, "rb") as f:
                    # Read and update hash string value in blocks of 4K
                    for byte_block in iter(lambda: f.read(4096), b""):
                        sha.update(byte_block)
            except Exception as ex:
                logging.error(ex)
                logging.error("Can not open file %r" % self.dsa.filename)
                self.signal_verify_status.emit(False)

        elif self.dsa.input_string:
            log += "Verifying message: %s\n" % self.dsa.input_string
            sha.update(self.dsa.input_string.encode("ascii"))

        digest = sha.hexdigest()
        log += "Digest: %s\n" % digest
        log += "Used Signature file: %s\n" % self.dsa.signature_filename
        if self.dsa.rsa.verify_data(self.dsa.signature, digest.encode("ascii")):
            log += "Authentic Message!\n\n"
        else:
            log += "Not authentic message!!!\n\n"
        logging.info(log)
        self.signal_verify_dsa.emit(self.dsa)
        self.signal_verify_text.emit(log)
        self.signal_verify_status.emit(True)
