import os
import logging
import textwrap

from SHA3 import sha3_224, sha3_256, sha3_384, sha3_512
from RSA import RSAKey, RSA
from utils import *
from design_gui import Ui_MainWindow

from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QFileDialog, QMessageBox

SHA_VER = {'SHA3-224': sha3_224,
           'SHA3-256': sha3_256,
           'SHA3-384': sha3_384,
           'SHA3-512': sha3_512}


class DSA:
    def __init__(self):
        self.config = {
            "e": "19853061807268348331",
            "sha": "SHA3-512",
            "key_size": "2048"
        }
        sha = SHA_VER[self.config["sha"]]
        self.set_sha(sha)
        self.KEYS = ['N', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qinv']

        self.file_data = None
        self.input_string = None
        self.signature = None
        self.signature_filename = None
        self.key = None
        self.rsa = None

    def set_sha(self, sha):
        self.sha = sha

    def set_key(self, key):
        self.key = key
        self.rsa = RSA(key)

    def log_key(self):
        def pref_generator(headline):
            yield headline
            prefspc = ' ' * len(headline)
            while True:
                yield prefspc

        def dump_attr(attrname, indent=0):
            val = getattr(self.key, attrname, None)
            if not val:
                return ' ' * indent + '%4s = None\n' % attrname
            else:
                headline = '\n' + ' ' * indent + '%4s = ' % attrname
                return '\n'.join(p + i for p, i in zip(pref_generator(headline), textwrap.wrap('0x%x,' % val)))

        log = ''
        for attr in self.KEYS:
            log += dump_attr(attr)
        log += '\n'
        return log

    def keygen(self, bits, e):
        if not bits:
            bits = self.config['key_size']
        if not e:
            e = self.config['e']
        key = RSAKey(bits=int(bits), e=int(e))
        self.set_key(key)
        self.config['key_state'] = 'private'

    def sign(self):
        sha = self.sha()
        log = ''

        if not self.file_data and not self.input_string:
            return False

        if self.file_data:
            try:
                log += 'Signing file %s\n' % self.file_data
                with open(self.file_data, "rb") as f:
                    # Read and update hash string value in blocks of 4K
                    for byte_block in iter(lambda: f.read(4096), b""):
                        sha.update(byte_block)
                file_data, input_string = self.file_data, None
            except Exception as ex:
                logging.error(ex)
                logging.error('Can not open file %r' % self.file_data)
                return False

        elif self.input_string:
            log += 'Signing message: %s\n' % self.input_string
            # self.file_data = 'message.txt'
            self.file_data = os.path.join(os.getcwd(), '../data/message.txt')
            with open(self.file_data, 'w') as f:
                f.write(self.input_string)
                log += 'Saved message to "message.txt"\n'
            sha.update(self.input_string.encode('ascii'))
            file_data, input_string = None, self.input_string

        digest = sha.hexdigest()
        log += 'Digest: %s\n' % digest
        signature = self.rsa.sign_data(digest.encode('ascii'))
        log += 'Signature: %s\n' % signature
        with open(f"{self.file_data}.sig", "wb") as f:
            f.write(signature)
            log += f'Saved signature to file {self.file_data}.sig\n'
        self.file_data, self.input_string = file_data, input_string
        return log

    def verify(self):
        sha = self.sha()
        log = ''

        if (not self.file_data and not self.input_string) or not self.signature:
            return False

        if self.file_data:
            try:
                log += 'Verifying file %s\n' % self.file_data
                with open(self.file_data, "rb") as f:
                    # Read and update hash string value in blocks of 4K
                    for byte_block in iter(lambda: f.read(4096), b""):
                        sha.update(byte_block)
            except Exception as ex:
                logging.error(ex)
                logging.error('Can not open file %r' % self.file_data)
                return False

        elif self.input_string:
            log += 'Verifying message: %s\n' % self.input_string
            sha.update(self.input_string.encode('ascii'))

        digest = sha.hexdigest()
        log += 'Digest: %s\n' % digest
        log += 'Used Signature file: %s\n' % self.signature_filename
        if self.rsa.verify_data(self.signature, digest.encode('ascii')):
            log += 'Authentic Message!\n'
        else:
            log += "Not authentic message!!!\n"
        return log


class GUI(Ui_MainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.dsa = DSA()

    def connect(self):
        self.load_key_btn.clicked.connect(self.load_key)
        self.save_key_btn.clicked.connect(self.save_key)
        self.generate_key.clicked.connect(self.keygen)
        self.sha_ver_combo.currentTextChanged.connect(self.change_sha)
        self.submit_string_btn.clicked.connect(self.submit_string)
        self.discard_input_btn.clicked.connect(self.discard_data)
        self.input_file_btn.clicked.connect(self.load_file)
        self.load_signature_btn.clicked.connect(self.load_signature)
        self.sign_btn.clicked.connect(self.sign)
        self.verify_btn.clicked.connect(self.verify)

    def load_key(self):
        file_filter = 'Key JSON File (*.json);; All Files (*)'
        filename, _ = QFileDialog.getOpenFileName(
            parent=self.rsa_key_group,
            caption='Select a file',
            directory='../keys',
            filter=file_filter,
            initialFilter='Key JSON File (*.json)'
        )
        key_type = self.key_type_combo.currentText()
        if not filename:
            return False
        try:
            key_dict = load_key_dict(filename)
        except Exception as ex:
            logging.error(ex)
            self.show_popup('Cannot open key file.', QMessageBox.Critical)
        if key_type == 'Public':
            if key_dict.get('e') and key_dict.get('N'):
                self.dsa.config['key_state'] = 'public'
                key = RSAKey(**key_dict)
                if key_dict.get('d'):
                    self.show_popup('WARNING: This key seems to contain private values.', QMessageBox.Warning)
            else:
                self.show_popup('Public key does not contain both e and N.', QMessageBox.Critical)
                return False

        elif key_type == 'Private':
            if key_dict.get('d') and key_dict.get('N'):
                self.dsa.config['key_state'] = 'private'
                key = RSAKey(**key_dict)
            else:
                self.show_popup('Private key does not contain enough values e, d and N.', QMessageBox.Critical)
                return False

        self.dsa.set_key(key)
        self.key_info.setText(self.dsa.log_key())

    def keygen(self):
        bits = self.key_size.value()
        e = self.e_value.toPlainText()
        logging.info(f'bits = {bits} . Type {type(bits)}')
        logging.info(f'e = {e} . Type {type(e)}')
        try:
            self.dsa.keygen(bits, e)
            print(self.dsa.log_key())
            self.key_info.setText(self.dsa.log_key())
        except Exception as ex:
            logging.error(ex)
            self.key_info.setText('Generating key pair failed.\n')
            self.show_popup('Cannot generate new key pair', QMessageBox.Critical)

    def show_popup(self, text, icon=QMessageBox.Question):
        msg = QMessageBox()
        msg.setWindowTitle('DSA')
        msg.setText(text)
        msg.setIcon(icon)
        msg.setStandardButtons(QMessageBox.Ok)
        _ = msg.exec_()

    def save_key(self):
        file_filter = 'Key JSON File (*.json);; All Files (*)'
        filename, _ = QFileDialog.getSaveFileName(
            parent=self.ds_group,
            caption='Write to file',
            directory='../keys',
            filter=file_filter,
            initialFilter='Key JSON File (*.json)'
        )
        if filename:
            filename = filename.rstrip('.json')
            try:
                self.dsa.key.private_to_json_file(f'{filename}.json')
                self.dsa.key.public_to_json_file(f'{filename}-public.json')
                self.show_popup(f'Dumped key to file {filename}.json and {filename}-public.json', QMessageBox.Information)
            except Exception as ex:
                logging.error(ex)
                self.show_popup('Cannot dump key to file', QMessageBox.Critical)
        else:
            self.show_popup('No file specified.')

    def change_sha(self):
        new_sha_ver = self.sha_ver_combo.currentText()
        logging.info(f'Change to variant {new_sha_ver}')
        new_sha = SHA_VER[new_sha_ver]
        self.dsa.set_sha(new_sha)

    def load_file(self):
        file_filter = 'All Files (*)'
        filename, _ = QFileDialog.getOpenFileName(
            parent=self.ds_group,
            caption='Select a file',
            directory='../data',
            filter=file_filter,
        )
        self.file_info.setText(filename)
        self.dsa.file_data = filename
        self.dsa.input_string = None
        self.input_string.setText('')
        logging.info(f'Chosen input file {filename}')

    def load_signature(self):
        file_filter = 'Signature Files (*.sig)'
        filename, _ = QFileDialog.getOpenFileName(
            parent=self.rsa_key_group,
            caption='Select a file',
            directory='../data',
            filter=file_filter,
        )
        self.signature_info.setText(filename)
        self.dsa.signature_filename = filename
        try:
            with open(filename, 'rb') as f:
                self.dsa.signature = f.read()
            logging.info(f'Loaded signature file {filename}')
        except Exception as ex:
            logging.error(ex)
            self.show_popup('Error when opening signature file.', QMessageBox.Critical)

    def submit_string(self):
        self.dsa.input_string = self.input_string.toPlainText()
        self.dsa.file_data = None
        self.file_info.setText('')
        logging.info(f'Submitted message: {self.dsa.input_string}')

    def discard_data(self):
        self.dsa.input_string = None
        self.dsa.file_data = None
        self.dsa.signature = None
        self.dsa.signature_filename = None
        self.signature_info.setText('')
        self.file_info.setText('')
        self.input_string.setText('')
        logging.info('Discarded all inputs.')

    def sign(self):
        if self.dsa.config['key_state'] == 'public':
            logging.warning('Signing requires private key!')
            self.dsa_info.append('\n\nSigning requires private key!\n\n')
            return

        logging.info('Signing message...')
        try:
            log = self.dsa.sign()
        except Exception as ex:
            log = 'Signing failed.'
            logging.error(ex)
        self.dsa_info.append('\n\n')
        self.dsa_info.append(log)

    def verify(self):
        logging.info('Verifying message...')
        try:
            log = self.dsa.verify()
        except Exception as ex:
            log = 'Verification failed.'
            logging.error(ex)
        self.dsa_info.append('\n\n')
        self.dsa_info.append(log)

if __name__ == "__main__":
    fmt = '[%(levelname)s] %(asctime)s - %(message)s'
    logging.basicConfig(level=logging.INFO, format=fmt)

    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = GUI()
    ui.setupUi(MainWindow)
    ui.connect()
    MainWindow.show()
    sys.exit(app.exec_())
