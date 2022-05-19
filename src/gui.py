import logging

from RSA import RSAKey
from utils import *
from design_gui import Ui_MainWindow
from workers_gui import DSA, KeygenWorker, SignWorker, VerifyWorker

from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QFileDialog, QMessageBox


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
