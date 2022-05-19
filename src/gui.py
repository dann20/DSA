import os
import logging
import textwrap
from dataclasses import dataclass, field
from typing import Callable, Protocol

from SHA3 import sha3_224, sha3_256, sha3_384, sha3_512, Keccak
from RSA import RSAKey, RSA
from utils import *
from design_gui import Ui_MainWindow

from PyQt5 import QtWidgets
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import QFileDialog, QMessageBox

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


class GUI(Ui_MainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.dsa = DSA()

    def connect(self):
        self.load_key_btn.clicked.connect(self.load_key)
        self.save_key_btn.clicked.connect(self.save_key)
        self.generate_key.clicked.connect(self.start_keygen_worker)
        self.sha_ver_combo.currentTextChanged.connect(self.change_sha)
        self.submit_string_btn.clicked.connect(self.submit_string)
        self.discard_input_btn.clicked.connect(self.discard_data)
        self.input_file_btn.clicked.connect(self.load_file)
        self.load_signature_btn.clicked.connect(self.load_signature)
        self.sign_btn.clicked.connect(self.start_sign_worker)
        self.verify_btn.clicked.connect(self.start_verify_worker)

    def set_dsa(self, dsa):
        self.dsa = dsa

    def load_key(self):
        file_filter = "Key JSON File (*.json);; All Files (*)"
        filename, _ = QFileDialog.getOpenFileName(
            parent=self.rsa_key_group,
            caption="Select a file",
            directory="../keys",
            filter=file_filter,
            initialFilter="Key JSON File (*.json)",
        )
        key_type = self.key_type_combo.currentText()
        if not filename:
            return False
        try:
            key_dict = load_key_dict(filename)
        except Exception as ex:
            logging.error(ex)
            self.show_popup("Cannot open key file.", QMessageBox.Critical)
            return False

        if key_type == "Public":
            if key_dict.get("e") and key_dict.get("N"):
                self.dsa.config["key_state"] = "public"
                key = RSAKey(**key_dict)
                if key_dict.get("d"):
                    self.show_popup(
                        "WARNING: This key seems to contain private values.",
                        QMessageBox.Warning,
                    )
            else:
                self.show_popup(
                    "Public key does not contain both e and N.", QMessageBox.Critical
                )
                return False

        elif key_type == "Private":
            if key_dict.get("d") and key_dict.get("N"):
                self.dsa.config["key_state"] = "private"
                key = RSAKey(**key_dict)
            else:
                self.show_popup(
                    "Private key does not contain enough values e, d and N.",
                    QMessageBox.Critical,
                )
                return False

        self.dsa.set_key(key)
        self.key_info.setText(self.dsa.log_key())

    def start_keygen_worker(self):
        bits = self.key_size.value()
        e = self.e_value.toPlainText()
        logging.info(f"keysize (bits) = {bits} . Type {type(bits)}")
        logging.info(f"e = {e} . Type {type(e)}")
        self.dsa.set_value_config("key_size", bits)
        self.dsa.set_value_config("e", e)
        self.worker_genkey = KeygenWorker(self.dsa)
        self.worker_genkey.signal_keygen_status.connect(self.handle_keygen_worker)
        self.worker_genkey.signal_keygen_dsa.connect(self.set_dsa)
        self.worker_genkey.start()

    def handle_keygen_worker(self, status):
        if not status:
            self.show_popup("Key generation failed.", QMessageBox.Critical)
        else:
            self.key_info.setText(self.dsa.log_key())

    def show_popup(self, text, icon=QMessageBox.Question):
        msg = QMessageBox()
        msg.setWindowTitle("DSA")
        msg.setText(text)
        msg.setIcon(icon)
        msg.setStandardButtons(QMessageBox.Ok)
        _ = msg.exec_()

    def save_key(self):
        file_filter = "Key JSON File (*.json);; All Files (*)"
        filename, _ = QFileDialog.getSaveFileName(
            parent=self.ds_group,
            caption="Write to file",
            directory="../keys",
            filter=file_filter,
            initialFilter="Key JSON File (*.json)",
        )
        if filename:
            filename = filename.rstrip(".json")
            try:
                self.dsa.key.private_to_json_file(f"{filename}.json")
                self.dsa.key.public_to_json_file(f"{filename}-public.json")
                self.show_popup(
                    f"Dumped key to file {filename}.json and {filename}-public.json",
                    QMessageBox.Information,
                )
            except Exception as ex:
                logging.error(ex)
                self.show_popup("Cannot dump key to file", QMessageBox.Critical)
        else:
            self.show_popup("No file specified.")

    def change_sha(self):
        new_sha_ver = self.sha_ver_combo.currentText()
        logging.info(f"Change to variant {new_sha_ver}")
        self.dsa.set_sha(new_sha_ver)

    def load_file(self):
        file_filter = "All Files (*)"
        filename, _ = QFileDialog.getOpenFileName(
            parent=self.ds_group,
            caption="Select a file",
            directory="../data",
            filter=file_filter,
        )
        self.file_info.setText(filename)
        self.dsa.filename = filename
        self.dsa.input_string = None
        self.input_string.setText("")
        logging.info(f"Chosen input file {filename}")

    def load_signature(self):
        file_filter = "Signature Files (*.sig)"
        filename, _ = QFileDialog.getOpenFileName(
            parent=self.rsa_key_group,
            caption="Select a file",
            directory="../data",
            filter=file_filter,
        )
        self.signature_info.setText(filename)
        self.dsa.signature_filename = filename
        try:
            with open(filename, "rb") as f:
                self.dsa.signature = f.read()
            logging.info(f"Loaded signature file {filename}")
        except Exception as ex:
            logging.error(ex)
            self.show_popup("Error when opening signature file.", QMessageBox.Critical)

    def submit_string(self):
        self.dsa.input_string = self.input_string.toPlainText()
        self.dsa.filename = None
        self.file_info.setText("")
        logging.info(f"Submitted message: {self.dsa.input_string}")

    def discard_data(self):
        self.dsa.input_string = None
        self.dsa.filename = None
        self.dsa.signature = None
        self.dsa.signature_filename = None
        self.signature_info.setText("")
        self.file_info.setText("")
        self.input_string.setText("")
        logging.info("Discarded all inputs.")

    def start_sign_worker(self):
        if self.dsa.config["key_state"] == "public":
            logging.warning("Signing requires private key!")
            self.dsa_info.append("\n\nSigning requires private key!\n\n")
            return False

        logging.info("Signing message...")
        self.worker_sign = SignWorker(self.dsa)
        self.worker_sign.signal_sign_status.connect(self.handle_sign_worker)
        self.worker_sign.signal_sign_dsa.connect(self.set_dsa)
        self.worker_sign.signal_sign_text.connect(self.dsa_info.append)
        self.worker_sign.start()

    def handle_sign_worker(self, status):
        if not status:
            self.show_popup("Sign failed.", QMessageBox.Critical)

    def start_verify_worker(self):
        logging.info("Verifying message...")
        self.worker_verify = VerifyWorker(self.dsa)
        self.worker_verify.signal_verify_status.connect(self.handle_verify_worker)
        self.worker_verify.signal_verify_dsa.connect(self.set_dsa)
        self.worker_verify.signal_verify_text.connect(self.dsa_info.append)
        self.worker_verify.start()

    def handle_verify_worker(self, status):
        if not status:
            self.show_popup("Verification failed.", QMessageBox.Critical)


if __name__ == "__main__":
    fmt = "[%(levelname)s] %(asctime)s - %(message)s"
    logging.basicConfig(level=logging.INFO, format=fmt)
    logging.info("Starting DSA GUI...")

    import sys

    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = GUI()
    ui.setupUi(MainWindow)
    ui.connect()
    MainWindow.show()
    sys.exit(app.exec_())
