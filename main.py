from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget, QVBoxLayout, QWidget, QTextEdit, QPushButton, QLabel
from PyQt5.QtCore import Qt

def vigenere_encrypt(text, keyword):
    alphabet = 'abcçdefgğhıijklmnoöpqrsştuvwxyz'
    encrypted_text = ''
    
    # Extend keyword to match length of text
    extended_keyword = ''
    for i in range(len(text)):
        extended_keyword += keyword[i % len(keyword)]
    
    for t_char, k_char in zip(text, extended_keyword):
        if t_char.lower() in alphabet:  # Only encrypt alphabetic characters
            shift = alphabet.index(k_char.lower())
            new_position = (alphabet.index(t_char.lower()) + shift) % 31
            encrypted_text += alphabet[new_position].upper() if t_char.isupper() else alphabet[new_position]
        else:
            encrypted_text += t_char

    return encrypted_text

def vigenere_decrypt(encrypted_text, keyword):
    alphabet = 'abcçdefgğhıijklmnoöpqrsştuvwxyz'
    decrypted_text = ''
    
    # Extend keyword to match length of text
    extended_keyword = ''
    for i in range(len(encrypted_text)):
        extended_keyword += keyword[i % len(keyword)]
    
    for e_char, k_char in zip(encrypted_text, extended_keyword):
        if e_char.lower() in alphabet:  # Only decrypt alphabetic characters
            shift = alphabet.index(k_char.lower())
            new_position = (alphabet.index(e_char.lower()) - shift) % 31
            decrypted_text += alphabet[new_position].upper() if e_char.isupper() else alphabet[new_position]
        else:
            decrypted_text += e_char

    return decrypted_text

class VigenereEncryptDecryptApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Encrypters')
        self.setGeometry(100, 100, 400, 400)
        
        layout = QVBoxLayout()
        tabs = QTabWidget()
        layout.addWidget(tabs)
        
        # Encryption tab
        self.encrypt_tab = QWidget()
        self.encrypt_layout = QVBoxLayout()
        
        self.encrypt_input = QTextEdit()
        self.encrypt_layout.addWidget(QLabel('Enter text to encrypt:'))
        self.encrypt_layout.addWidget(self.encrypt_input)

        self.encrypt_keyword = QTextEdit()
        self.encrypt_keyword.setFixedHeight(50)
        self.encrypt_layout.addWidget(QLabel('Enter keyword(can onyl contain english letters):'))
        self.encrypt_layout.addWidget(self.encrypt_keyword)
        
        self.encrypt_button = QPushButton('Encrypt')
        self.encrypt_button.clicked.connect(self.perform_encryption)
        self.encrypt_layout.addWidget(self.encrypt_button)
        
        self.encrypt_output = QTextEdit()
        self.encrypt_output.setReadOnly(True)
        self.encrypt_layout.addWidget(QLabel('Encrypted text:'))
        self.encrypt_layout.addWidget(self.encrypt_output)
        
        self.encrypt_tab.setLayout(self.encrypt_layout)
        tabs.addTab(self.encrypt_tab, 'Encrypt')
        
        # Decryption tab
        self.decrypt_tab = QWidget()
        self.decrypt_layout = QVBoxLayout()
        
        self.decrypt_input = QTextEdit()
        self.decrypt_layout.addWidget(QLabel('Enter text to decrypt:'))
        self.decrypt_layout.addWidget(self.decrypt_input)

        self.decrypt_keyword = QTextEdit()
        self.decrypt_keyword.setFixedHeight(50)
        self.decrypt_layout.addWidget(QLabel('Enter keyword:'))
        self.decrypt_layout.addWidget(self.decrypt_keyword)
        
        self.decrypt_button = QPushButton('Decrypt')
        self.decrypt_button.clicked.connect(self.perform_decryption)
        self.decrypt_layout.addWidget(self.decrypt_button)
        
        self.decrypt_output = QTextEdit()
        self.decrypt_output.setReadOnly(True)
        self.decrypt_layout.addWidget(QLabel('Decrypted text:'))
        self.decrypt_layout.addWidget(self.decrypt_output)
        
        self.decrypt_tab.setLayout(self.decrypt_layout)
        tabs.addTab(self.decrypt_tab, 'Decrypt')
        
        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def perform_encryption(self):
        text = self.encrypt_input.toPlainText()
        keyword = self.encrypt_keyword.toPlainText().strip()
        encrypted_text = vigenere_encrypt(text, keyword)
        self.encrypt_output.setPlainText(encrypted_text)

    def perform_decryption(self):
        text = self.decrypt_input.toPlainText()
        keyword = self.decrypt_keyword.toPlainText().strip()
        decrypted_text = vigenere_decrypt(text, keyword)
        self.decrypt_output.setPlainText(decrypted_text)

if __name__ == '__main__':
    app = QApplication([])
    mainWin = VigenereEncryptDecryptApp()
    mainWin.show()
    app.exec_()
