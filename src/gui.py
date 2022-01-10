# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '.\main.ui'
#
# Created by: PyQt5 UI code generator 5.15.4
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(814, 800)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.rsa_key_group = QtWidgets.QGroupBox(self.centralwidget)
        self.rsa_key_group.setGeometry(QtCore.QRect(10, 80, 791, 371))
        font = QtGui.QFont()
        font.setFamily("mononoki Nerd Font")
        font.setPointSize(12)
        self.rsa_key_group.setFont(font)
        self.rsa_key_group.setObjectName("rsa_key_group")
        self.generate_key = QtWidgets.QPushButton(self.rsa_key_group)
        self.generate_key.setGeometry(QtCore.QRect(280, 330, 111, 31))
        self.generate_key.setObjectName("generate_key")
        self.load_key_btn = QtWidgets.QPushButton(self.rsa_key_group)
        self.load_key_btn.setGeometry(QtCore.QRect(570, 330, 111, 31))
        self.load_key_btn.setObjectName("load_key_btn")
        self.key_size = QtWidgets.QSpinBox(self.rsa_key_group)
        self.key_size.setGeometry(QtCore.QRect(140, 330, 71, 31))
        self.key_size.setMaximum(4096)
        self.key_size.setProperty("value", 2048)
        self.key_size.setObjectName("key_size")
        self.key_size_lbl = QtWidgets.QLabel(self.rsa_key_group)
        self.key_size_lbl.setGeometry(QtCore.QRect(60, 330, 81, 31))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.key_size_lbl.setFont(font)
        self.key_size_lbl.setObjectName("key_size_lbl")
        self.key_size_lbl_2 = QtWidgets.QLabel(self.rsa_key_group)
        self.key_size_lbl_2.setGeometry(QtCore.QRect(220, 330, 81, 31))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.key_size_lbl_2.setFont(font)
        self.key_size_lbl_2.setObjectName("key_size_lbl_2")
        self.scrollArea = QtWidgets.QScrollArea(self.rsa_key_group)
        self.scrollArea.setGeometry(QtCore.QRect(10, 30, 771, 291))
        self.scrollArea.setWidgetResizable(True)
        self.scrollArea.setObjectName("scrollArea")
        self.scrollAreaWidgetContents = QtWidgets.QWidget()
        self.scrollAreaWidgetContents.setGeometry(QtCore.QRect(0, 0, 769, 289))
        self.scrollAreaWidgetContents.setObjectName("scrollAreaWidgetContents")
        self.key_info = QtWidgets.QTextBrowser(self.scrollAreaWidgetContents)
        self.key_info.setGeometry(QtCore.QRect(0, 0, 771, 291))
        self.key_info.setObjectName("key_info")
        self.scrollArea.setWidget(self.scrollAreaWidgetContents)
        self.save_key_btn = QtWidgets.QPushButton(self.rsa_key_group)
        self.save_key_btn.setGeometry(QtCore.QRect(410, 330, 111, 31))
        self.save_key_btn.setObjectName("save_key_btn")
        self.key_type_combo = QtWidgets.QComboBox(self.rsa_key_group)
        self.key_type_combo.setGeometry(QtCore.QRect(690, 330, 81, 31))
        self.key_type_combo.setObjectName("key_type_combo")
        self.key_type_combo.addItem("")
        self.key_type_combo.addItem("")
        self.key_type_combo.addItem("")
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
        self.ds_group.setGeometry(QtCore.QRect(10, 460, 791, 331))
        font = QtGui.QFont()
        font.setFamily("mononoki Nerd Font")
        font.setPointSize(12)
        self.ds_group.setFont(font)
        self.ds_group.setObjectName("ds_group")
        self.discard_input_btn = QtWidgets.QPushButton(self.ds_group)
        self.discard_input_btn.setEnabled(False)
        self.discard_input_btn.setGeometry(QtCore.QRect(630, 40, 141, 31))
        self.discard_input_btn.setObjectName("discard_input_btn")
        self.input_string_lbl = QtWidgets.QLabel(self.ds_group)
        self.input_string_lbl.setGeometry(QtCore.QRect(20, 40, 111, 21))
        self.input_string_lbl.setObjectName("input_string_lbl")
        self.input_string = QtWidgets.QTextEdit(self.ds_group)
        self.input_string.setGeometry(QtCore.QRect(140, 30, 431, 41))
        self.input_string.setObjectName("input_string")
        self.scrollArea_2 = QtWidgets.QScrollArea(self.ds_group)
        self.scrollArea_2.setGeometry(QtCore.QRect(10, 80, 771, 161))
        self.scrollArea_2.setWidgetResizable(True)
        self.scrollArea_2.setObjectName("scrollArea_2")
        self.scrollAreaWidgetContents_2 = QtWidgets.QWidget()
        self.scrollAreaWidgetContents_2.setGeometry(QtCore.QRect(0, 0, 769, 159))
        self.scrollAreaWidgetContents_2.setObjectName("scrollAreaWidgetContents_2")
        self.ds_info = QtWidgets.QTextBrowser(self.scrollAreaWidgetContents_2)
        self.ds_info.setGeometry(QtCore.QRect(0, 0, 771, 161))
        self.ds_info.setObjectName("ds_info")
        self.scrollArea_2.setWidget(self.scrollAreaWidgetContents_2)
        self.load_file_btn = QtWidgets.QPushButton(self.ds_group)
        self.load_file_btn.setGeometry(QtCore.QRect(80, 290, 111, 31))
        self.load_file_btn.setObjectName("load_file_btn")
        self.load_signature_btn = QtWidgets.QPushButton(self.ds_group)
        self.load_signature_btn.setGeometry(QtCore.QRect(330, 290, 141, 31))
        self.load_signature_btn.setObjectName("load_signature_btn")
        self.sign_btn = QtWidgets.QPushButton(self.ds_group)
        self.sign_btn.setEnabled(False)
        self.sign_btn.setGeometry(QtCore.QRect(580, 270, 81, 31))
        self.sign_btn.setObjectName("sign_btn")
        self.verify_btn = QtWidgets.QPushButton(self.ds_group)
        self.verify_btn.setEnabled(False)
        self.verify_btn.setGeometry(QtCore.QRect(680, 270, 91, 31))
        self.verify_btn.setObjectName("verify_btn")
        self.file_info = QtWidgets.QTextBrowser(self.ds_group)
        self.file_info.setGeometry(QtCore.QRect(30, 250, 211, 31))
        self.file_info.setObjectName("file_info")
        self.signature_info = QtWidgets.QTextBrowser(self.ds_group)
        self.signature_info.setGeometry(QtCore.QRect(290, 250, 221, 31))
        self.signature_info.setObjectName("signature_info")
        self.scrollArea_2.raise_()
        self.discard_input_btn.raise_()
        self.input_string_lbl.raise_()
        self.input_string.raise_()
        self.load_file_btn.raise_()
        self.load_signature_btn.raise_()
        self.sign_btn.raise_()
        self.verify_btn.raise_()
        self.file_info.raise_()
        self.signature_info.raise_()
        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.rsa_key_group.setTitle(_translate("MainWindow", "RSA Key Configuration"))
        self.generate_key.setText(_translate("MainWindow", "Generate"))
        self.load_key_btn.setText(_translate("MainWindow", "Load Key"))
        self.key_size_lbl.setText(_translate("MainWindow", "Key Size"))
        self.key_size_lbl_2.setText(_translate("MainWindow", "bits"))
        self.save_key_btn.setText(_translate("MainWindow", "Save Key"))
        self.key_type_combo.setItemText(0, _translate("MainWindow", "Public"))
        self.key_type_combo.setItemText(1, _translate("MainWindow", "Private"))
        self.key_type_combo.setItemText(2, _translate("MainWindow", "Full"))
        self.sha_group.setTitle(_translate("MainWindow", "SHA3 Configuration"))
        self.sha_ver_combo.setItemText(0, _translate("MainWindow", "SHA3-512"))
        self.sha_ver_combo.setItemText(1, _translate("MainWindow", "SHA3-224"))
        self.sha_ver_combo.setItemText(2, _translate("MainWindow", "SHA3-256"))
        self.sha_ver_combo.setItemText(3, _translate("MainWindow", "SHA3-384"))
        self.sha_lbl.setText(_translate("MainWindow", "Choose SHA-3 variant"))
        self.ds_group.setTitle(_translate("MainWindow", "Sign - Verify Data"))
        self.discard_input_btn.setText(_translate("MainWindow", "Discard input"))
        self.input_string_lbl.setText(_translate("MainWindow", "Input string"))
        self.load_file_btn.setText(_translate("MainWindow", "Load File"))
        self.load_signature_btn.setText(_translate("MainWindow", "Load Signature"))
        self.sign_btn.setText(_translate("MainWindow", "Sign"))
        self.verify_btn.setText(_translate("MainWindow", "Verify"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())