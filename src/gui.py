import os
import logging
import textwrap

from SHA3 import sha3_224, sha3_256, sha3_384, sha3_512
from RSA import RSAKey, RSA
from utils import *

from PyQt5 import QtCore, QtGui, QtWidgets
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


class Ui_MainWindow(object):
    def __init__(self) -> None:
        super().__init__()
        self.dsa = DSA()

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("DSA using SHA3-RSA")
        MainWindow.resize(814, 822)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.rsa_key_group = QtWidgets.QGroupBox(self.centralwidget)
        self.rsa_key_group.setGeometry(QtCore.QRect(10, 80, 791, 371))
        font = QtGui.QFont()
        font.setFamily("mononoki Nerd Font")
        font.setPointSize(12)
        self.rsa_key_group.setFont(font)
        self.rsa_key_group.setObjectName("rsa_key_group")
        self.load_key_btn = QtWidgets.QPushButton(self.rsa_key_group)
        self.load_key_btn.setGeometry(QtCore.QRect(150, 330, 111, 31))
        self.load_key_btn.setObjectName("load_key_btn")
        self.key_size = QtWidgets.QSpinBox(self.rsa_key_group)
        self.key_size.setGeometry(QtCore.QRect(120, 30, 71, 31))
        self.key_size.setMaximum(4096)
        self.key_size.setProperty("value", 2048)
        self.key_size.setObjectName("key_size")
        self.key_size_lbl = QtWidgets.QLabel(self.rsa_key_group)
        self.key_size_lbl.setGeometry(QtCore.QRect(40, 30, 81, 31))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.key_size_lbl.setFont(font)
        self.key_size_lbl.setObjectName("key_size_lbl")
        self.key_size_lbl_2 = QtWidgets.QLabel(self.rsa_key_group)
        self.key_size_lbl_2.setGeometry(QtCore.QRect(200, 30, 81, 31))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.key_size_lbl_2.setFont(font)
        self.key_size_lbl_2.setObjectName("key_size_lbl_2")
        self.scrollArea = QtWidgets.QScrollArea(self.rsa_key_group)
        self.scrollArea.setGeometry(QtCore.QRect(10, 70, 771, 251))
        self.scrollArea.setWidgetResizable(True)
        self.scrollArea.setObjectName("scrollArea")
        self.scrollAreaWidgetContents = QtWidgets.QWidget()
        self.scrollAreaWidgetContents.setGeometry(QtCore.QRect(0, 0, 769, 249))
        self.scrollAreaWidgetContents.setObjectName("scrollAreaWidgetContents")
        self.key_info = QtWidgets.QTextEdit(self.scrollAreaWidgetContents)
        self.key_info.setEnabled(True)
        self.key_info.setGeometry(QtCore.QRect(0, 0, 771, 251))
        self.key_info.setReadOnly(True)
        self.key_info.setObjectName("key_info")
        self.scrollArea.setWidget(self.scrollAreaWidgetContents)
        self.save_key_btn = QtWidgets.QPushButton(self.rsa_key_group)
        self.save_key_btn.setGeometry(QtCore.QRect(530, 330, 111, 31))
        self.save_key_btn.setObjectName("save_key_btn")
        self.key_type_combo = QtWidgets.QComboBox(self.rsa_key_group)
        self.key_type_combo.setGeometry(QtCore.QRect(350, 330, 95, 31))
        self.key_type_combo.setObjectName("key_type_combo")
        self.key_type_combo.addItem("")
        self.key_type_combo.addItem("")
        self.key_size_lbl_4 = QtWidgets.QLabel(self.rsa_key_group)
        self.key_size_lbl_4.setGeometry(QtCore.QRect(280, 30, 41, 31))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.key_size_lbl_4.setFont(font)
        self.key_size_lbl_4.setObjectName("key_size_lbl_4")
        self.e_value = QtWidgets.QTextEdit(self.rsa_key_group)
        self.e_value.setGeometry(QtCore.QRect(320, 30, 311, 31))
        self.e_value.setObjectName("e_value")
        self.generate_key = QtWidgets.QPushButton(self.rsa_key_group)
        self.generate_key.setGeometry(QtCore.QRect(670, 30, 111, 31))
        self.generate_key.setObjectName("generate_key")
        self.sha_group = QtWidgets.QGroupBox(self.centralwidget)
        self.sha_group.setGeometry(QtCore.QRect(10, 10, 791, 61))
        font = QtGui.QFont()
        font.setFamily("mononoki Nerd Font")
        font.setPointSize(12)
        self.sha_group.setFont(font)
        self.sha_group.setObjectName("sha_group")
        self.sha_ver_combo = QtWidgets.QComboBox(self.sha_group)
        self.sha_ver_combo.setGeometry(QtCore.QRect(390, 20, 121, 31))
        self.sha_ver_combo.setObjectName("sha_ver_combo")
        self.sha_ver_combo.addItem("")
        self.sha_ver_combo.addItem("")
        self.sha_ver_combo.addItem("")
        self.sha_ver_combo.addItem("")
        self.sha_lbl = QtWidgets.QLabel(self.sha_group)
        self.sha_lbl.setGeometry(QtCore.QRect(190, 20, 191, 31))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.sha_lbl.setFont(font)
        self.sha_lbl.setObjectName("sha_lbl")
        self.ds_group = QtWidgets.QGroupBox(self.centralwidget)
        self.ds_group.setGeometry(QtCore.QRect(10, 460, 791, 361))
        font = QtGui.QFont()
        font.setFamily("mononoki Nerd Font")
        font.setPointSize(12)
        self.ds_group.setFont(font)
        self.ds_group.setObjectName("ds_group")
        self.discard_input_btn = QtWidgets.QPushButton(self.ds_group)
        self.discard_input_btn.setEnabled(True)
        self.discard_input_btn.setGeometry(QtCore.QRect(690, 30, 91, 61))
        self.discard_input_btn.setObjectName("discard_input_btn")
        self.input_string_lbl = QtWidgets.QLabel(self.ds_group)
        self.input_string_lbl.setGeometry(QtCore.QRect(20, 30, 111, 61))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setItalic(True)
        font.setUnderline(False)
        self.input_string_lbl.setFont(font)
        self.input_string_lbl.setObjectName("input_string_lbl")
        self.input_string = QtWidgets.QTextEdit(self.ds_group)
        self.input_string.setGeometry(QtCore.QRect(140, 30, 431, 61))
        self.input_string.setObjectName("input_string")
        self.scrollArea_2 = QtWidgets.QScrollArea(self.ds_group)
        self.scrollArea_2.setGeometry(QtCore.QRect(10, 100, 771, 161))
        self.scrollArea_2.setWidgetResizable(True)
        self.scrollArea_2.setObjectName("scrollArea_2")
        self.scrollAreaWidgetContents_2 = QtWidgets.QWidget()
        self.scrollAreaWidgetContents_2.setGeometry(QtCore.QRect(0, 0, 769, 159))
        self.scrollAreaWidgetContents_2.setObjectName("scrollAreaWidgetContents_2")
        self.dsa_info = QtWidgets.QTextEdit(self.scrollAreaWidgetContents_2)
        self.dsa_info.setGeometry(QtCore.QRect(0, 0, 771, 161))
        self.dsa_info.setReadOnly(True)
        self.dsa_info.setObjectName("dsa_info")
        self.scrollArea_2.setWidget(self.scrollAreaWidgetContents_2)
        self.input_file_btn = QtWidgets.QPushButton(self.ds_group)
        self.input_file_btn.setGeometry(QtCore.QRect(20, 280, 141, 31))
        self.input_file_btn.setObjectName("input_file_btn")
        self.load_signature_btn = QtWidgets.QPushButton(self.ds_group)
        self.load_signature_btn.setGeometry(QtCore.QRect(20, 320, 141, 31))
        self.load_signature_btn.setObjectName("load_signature_btn")
        self.sign_btn = QtWidgets.QPushButton(self.ds_group)
        self.sign_btn.setEnabled(True)
        self.sign_btn.setGeometry(QtCore.QRect(630, 280, 121, 31))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.sign_btn.setFont(font)
        self.sign_btn.setObjectName("sign_btn")
        self.verify_btn = QtWidgets.QPushButton(self.ds_group)
        self.verify_btn.setEnabled(True)
        self.verify_btn.setGeometry(QtCore.QRect(630, 320, 121, 31))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.verify_btn.setFont(font)
        self.verify_btn.setObjectName("verify_btn")
        self.file_info = QtWidgets.QTextEdit(self.ds_group)
        self.file_info.setGeometry(QtCore.QRect(170, 280, 421, 31))
        self.file_info.setObjectName("file_info")
        self.signature_info = QtWidgets.QTextEdit(self.ds_group)
        self.signature_info.setGeometry(QtCore.QRect(170, 320, 421, 31))
        self.signature_info.setObjectName("signature_info")
        self.submit_string_btn = QtWidgets.QPushButton(self.ds_group)
        self.submit_string_btn.setEnabled(True)
        self.submit_string_btn.setGeometry(QtCore.QRect(580, 30, 101, 61))
        self.submit_string_btn.setObjectName("submit_string_btn")
        self.signature_info.raise_()
        self.file_info.raise_()
        self.scrollArea_2.raise_()
        self.discard_input_btn.raise_()
        self.input_string_lbl.raise_()
        self.input_string.raise_()
        self.input_file_btn.raise_()
        self.load_signature_btn.raise_()
        self.sign_btn.raise_()
        self.verify_btn.raise_()
        self.submit_string_btn.raise_()
        MainWindow.setCentralWidget(self.centralwidget)

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

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("DSA using SHA3-RSA", "DSA using SHA3-RSA"))
        self.rsa_key_group.setTitle(_translate("DSA using SHA3-RSA", "RSA Key Configuration"))
        self.load_key_btn.setText(_translate("DSA using SHA3-RSA", "Load Key"))
        self.key_size_lbl.setText(_translate("DSA using SHA3-RSA", "Key Size"))
        self.key_size_lbl_2.setText(_translate("DSA using SHA3-RSA", "bits"))
        self.save_key_btn.setText(_translate("DSA using SHA3-RSA", "Save Key"))
        self.key_type_combo.setItemText(0, _translate("DSA using SHA3-RSA", "Public"))
        self.key_type_combo.setItemText(1, _translate("DSA using SHA3-RSA", "Private"))
        self.key_size_lbl_4.setText(_translate("DSA using SHA3-RSA", "e ="))
        self.e_value.setHtml(_translate("DSA using SHA3-RSA", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'mononoki Nerd Font\'; font-size:12pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">19853061807268348331</p></body></html>"))
        self.generate_key.setText(_translate("DSA using SHA3-RSA", "Generate"))
        self.sha_group.setTitle(_translate("DSA using SHA3-RSA", "SHA3 Configuration"))
        self.sha_ver_combo.setItemText(0, _translate("DSA using SHA3-RSA", "SHA3-512"))
        self.sha_ver_combo.setItemText(1, _translate("DSA using SHA3-RSA", "SHA3-384"))
        self.sha_ver_combo.setItemText(2, _translate("DSA using SHA3-RSA", "SHA3-256"))
        self.sha_ver_combo.setItemText(3, _translate("DSA using SHA3-RSA", "SHA3-224"))
        self.sha_lbl.setText(_translate("DSA using SHA3-RSA", "Choose SHA-3 variant"))
        self.ds_group.setTitle(_translate("DSA using SHA3-RSA", "Sign - Verify Data"))
        self.discard_input_btn.setText(_translate("DSA using SHA3-RSA", "Discard\n"
"Inputs"))
        self.input_string_lbl.setText(_translate("DSA using SHA3-RSA", "Input string"))
        self.input_file_btn.setText(_translate("DSA using SHA3-RSA", "Input File"))
        self.load_signature_btn.setText(_translate("DSA using SHA3-RSA", "Load Signature"))
        self.sign_btn.setText(_translate("DSA using SHA3-RSA", "Sign"))
        self.verify_btn.setText(_translate("DSA using SHA3-RSA", "Verify"))
        self.submit_string_btn.setText(_translate("DSA using SHA3-RSA", "Submit\n"
"String"))

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
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
