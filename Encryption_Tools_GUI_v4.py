import os
import sys
import datetime
import hashlib # 導入 hashlib 模組用於計算雜湊值
# 導入用於分塊加密/解密的 Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag # 導入 InvalidTag 異常
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QLineEdit, QTextEdit, QFileDialog, QCheckBox
)
from PyQt6.QtCore import Qt,QSize
from PyQt6.QtGui import QIcon, QFont

# ====== 設定變數 ======
SUFFIX = '.bwpsen'
KEY_FOLDER = 'Key'
LOG_FILE = 'Encryption_Tools_Log.txt'
HASH_LENGTH = 32 # SHA256 雜湊值長度為 32 bytes
CHUNK_SIZE = 1 * 1024 * 1024 # 每次讀寫的塊大小 (1 MB)，可根據需要調整

# ====== 工具函式 ======
def get_base_dir():
    """取得應用程式的基礎目錄，兼容 PyInstaller 打包。"""
    if getattr(sys, 'frozen', False):  # PyInstaller 打包執行
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def get_key_dir():
    """取得金鑰儲存目錄，如果不存在則創建。"""
    path = os.path.join(get_base_dir(), KEY_FOLDER)
    os.makedirs(path, exist_ok=True)
    return path

def log_action(action: str, filepath: str, key_identifier: str = "N/A"):
    """將加密/解密操作記錄到日誌檔，並包含金鑰識別碼。"""
    full_path = os.path.abspath(filepath)
    size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # 在日誌中包含金鑰識別碼
    log_line = f"[{timestamp}] {action.upper()} | {os.path.basename(filepath)} | {full_path} | {size} bytes | Key ID: {key_identifier}\n"
    with open(os.path.join(get_base_dir(), LOG_FILE), 'a', encoding='utf-8') as f:
        f.write(log_line)

def calculate_file_hash(file_path: str) -> bytes:
    """計算檔案內容的 SHA256 雜湊值，透過分塊讀取以支援大檔案。"""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.digest() # 返回二進制雜湊值 (32 bytes)
    except FileNotFoundError:
        raise FileNotFoundError(f"檔案未找到: {file_path}")
    except Exception as e:
        raise IOError(f"讀取檔案進行雜湊計算時發生錯誤: {e}")

# ====== 金鑰衍生功能 ======
def generate_random_key() -> bytes:
    """生成一個隨機的 AESGCM 金鑰 (256 bits)。"""
    return os.urandom(32) # AES-256 需要 32 bytes 的金鑰

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    從使用者提供的密碼和一個隨機鹽值衍生出一個安全的金鑰。
    使用 PBKDF2HMAC (密碼型金鑰衍生函式)。
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits for AES-256
        salt=salt,
        iterations=480000,  # 建議至少 480000 次迭代以增加安全性
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8')) # 將密碼字串編碼為位元組

# ====== 加解密功能 ======
def encrypt_file_logic(file_path: str, password: str | None = None):
    """
    執行檔案加密邏輯 (分塊處理以支援大檔案)。
    如果提供了密碼，則使用密碼加密；否則使用隨機金鑰。
    加密後的檔案將包含原始檔案內容的 SHA256 雜湊值、nonce 以及 GCM 認證標籤。
    """
    if file_path.endswith(SUFFIX):
        return {"status": "warning", "message": "file_already_encrypted"}

    try:
        # 先計算原始檔案的雜湊值 (分塊讀取)
        original_file_content_hash = calculate_file_hash(file_path)
    except FileNotFoundError:
        return {"status": "error", "message": "file_not_found", "details": file_path}
    except IOError as e:
        return {"status": "error", "message": "file_read_error", "details": str(e)}

    nonce = os.urandom(12) # AESGCM 的 nonce (Initialization Vector)

    key_identifier_for_log = ""
    salt = b'' # 預設為空位元組

    if password:
        salt = os.urandom(16) # 產生 16 bytes 的隨機鹽值
        key = derive_key_from_password(password, salt)
        log_method = 'encrypt_with_password'
        key_identifier_for_log = "password" # 密碼加密的金鑰識別碼
    else:
        key = generate_random_key()
        log_method = 'encrypt_with_keyfile'
        key_identifier_for_log = original_file_content_hash.hex() # 隨機金鑰的金鑰識別碼 (雜湊值)
    
    # 初始化 AES-GCM Cipher
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    encrypted_path = file_path + SUFFIX
    try:
        with open(file_path, 'rb') as infile, open(encrypted_path, 'wb') as outfile:
            # 寫入檔案頭部
            outfile.write(original_file_content_hash) # 32 bytes
            if password:
                outfile.write(salt) # 16 bytes (僅限密碼模式)
            outfile.write(nonce) # 12 bytes

            # 分塊讀取、加密並寫入
            while True:
                chunk = infile.read(CHUNK_SIZE)
                if not chunk:
                    break
                encrypted_chunk = encryptor.update(chunk)
                outfile.write(encrypted_chunk)
            
            # 寫入任何剩餘的加密資料 (如果最後一個塊小於 CHUNK_SIZE) 和認證標籤
            remaining_encrypted_data = encryptor.finalize()
            outfile.write(remaining_encrypted_data)
            outfile.write(encryptor.tag) # 16 bytes GCM 認證標籤

        os.remove(file_path) # 成功加密後刪除原始檔案
    except Exception as e:
        # 如果在寫入或刪除過程中失敗，嘗試刪除可能已創建的部分加密檔案
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)
        return {"status": "error", "message": "write_delete_failed", "details": str(e)}

    if not password: # 如果是隨機金鑰模式，則儲存金鑰檔
        # 金鑰檔名稱現在基於原始檔案的內容雜湊值
        key_filename = original_file_content_hash.hex() + '.key' 
        key_path = os.path.join(get_key_dir(), key_filename)
        try:
            with open(key_path, 'wb') as f:
                f.write(key)
        except Exception as e:
            # 即使金鑰儲存失敗，加密仍成功，但日誌中會記錄部分成功
            log_action('encrypt_partial_success', encrypted_path, key_identifier_for_log) 
            return {"status": "partial_success", "message": "key_save_failed", "details": str(e),
                            "encrypted_path": encrypted_path, "key_path_attempted": key_path, 
                            "original_hash": original_file_content_hash.hex()}
        # 成功加密並儲存金鑰後記錄日誌
        log_action(log_method, encrypted_path, key_identifier_for_log)
        return {"status": "success", "encrypted_path": encrypted_path, "key_path": key_path, 
                "method": "keyfile", "original_hash": original_file_content_hash.hex()}
    else: # 密碼加密模式，不需要儲存金鑰檔
        # 密碼加密成功後記錄日誌
        log_action(log_method, encrypted_path, key_identifier_for_log)
        return {"status": "success", "encrypted_path": encrypted_path, 
                "method": "password", "original_hash": original_file_content_hash.hex()}


def decrypt_file_logic(file_path: str, key_path_input: str = "", password: str | None = None):
    """
    執行檔案解密邏輯 (分塊處理以支援大檔案)。
    會根據提供的密碼參數，自動判斷是密碼解密還是金鑰檔解密。
    從加密檔案中讀取原始檔案的雜湊值來確定金鑰檔。
    """
    if not file_path.endswith(SUFFIX):
        return {"status": "error", "message": "not_encrypted_file"}

    original_path = file_path[:-len(SUFFIX)]
    
    key_identifier_for_log = "" # 定義金鑰識別碼變數

    try:
        with open(file_path, 'rb') as infile:
            # 讀取原始檔案雜湊值 (32 bytes)
            extracted_hash = infile.read(HASH_LENGTH)
            if len(extracted_hash) < HASH_LENGTH:
                return {"status": "error", "message": "invalid_encrypted_file_format", 
                                "details": "加密檔案過短，無法提取內容雜湊值。"}
            
            salt = b''
            if password:
                # 密碼加密模式下，讀取鹽值 (16 bytes)
                salt = infile.read(16)
                if len(salt) < 16:
                    return {"status": "error", "message": "invalid_encrypted_file_format", 
                                    "details": "檔案格式不符密碼加密模式，無法提取鹽值。"}
                
            # 讀取 Nonce (12 bytes)
            nonce = infile.read(12)
            if len(nonce) < 12:
                return {"status": "error", "message": "invalid_encrypted_file_format", 
                                "details": "加密檔案過短，無法提取 Nonce。"}

            # 讀取金鑰
            key = None
            if password:
                key = derive_key_from_password(password, salt)
                log_method = 'decrypt_with_password'
                key_identifier_for_log = "password"
            else:
                log_method = 'decrypt_with_keyfile'
                key_identifier_for_log = extracted_hash.hex() # 隨機金鑰的金鑰識別碼 (雜湊值)

                key_to_load_path = ""
                if key_path_input: # 使用者手動指定金鑰檔案
                    key_to_load_path = key_path_input
                else: # 嘗試使用基於雜湊的預設金鑰檔案
                    default_key_filename = extracted_hash.hex() + '.key'
                    key_to_load_path = os.path.join(get_key_dir(), default_key_filename)
                
                try:
                    with open(key_to_load_path, 'rb') as kf:
                        key = kf.read()
                except FileNotFoundError:
                    return {"status": "error", "message": "key_file_not_found", "details": key_to_load_path}
                except Exception as e:
                    return {"status": "error", "message": "key_file_read_error", "details": str(e)}

            if key is None:
                return {"status": "error", "message": "key_unavailable", "details": "金鑰無法獲取。"}

            # 獲取檔案大小以讀取 GCM Tag
            infile.seek(0, os.SEEK_END) # 跳到檔案末尾
            total_encrypted_file_size = infile.tell()
            tag_start_position = total_encrypted_file_size - 16 # GCM Tag 是 16 bytes

            if tag_start_position < (HASH_LENGTH + (16 if password else 0) + 12):
                return {"status": "error", "message": "invalid_encrypted_file_format",
                                "details": "加密檔案過短，無法提取 GCM 認證標籤。"}

            infile.seek(tag_start_position) # 跳到 GCM Tag 的位置
            tag = infile.read(16)
            if len(tag) < 16:
                return {"status": "error", "message": "invalid_encrypted_file_format",
                                "details": "未能成功讀取 GCM 認證標籤。"}
            
            # 將讀取指針移回加密數據的開始位置
            infile.seek(HASH_LENGTH + (16 if password else 0) + 12)

            # 初始化 AES-GCM Cipher，並傳入 tag 進行驗證
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()

            with open(original_path, 'wb') as outfile:
                # 分塊讀取、解密並寫入
                while infile.tell() < tag_start_position: # 確保不讀取到 tag 部分
                    bytes_to_read = min(CHUNK_SIZE, tag_start_position - infile.tell())
                    if bytes_to_read == 0:
                        break # 已讀完所有加密資料
                    chunk = infile.read(bytes_to_read)
                    if not chunk:
                        break # 意外結束
                    decrypted_chunk = decryptor.update(chunk)
                    outfile.write(decrypted_chunk)
                
                # 最終化解密器，它會在此處驗證 GCM 認證標籤
                remaining_decrypted_data = decryptor.finalize()
                outfile.write(remaining_decrypted_data)

        os.remove(file_path) # 成功解密後刪除原始加密檔案
    except InvalidTag as e:
        # GCM 認證失敗，表示密碼不正確或檔案被篡改
        return {"status": "error", "message": "decryption_failed", 
                        "details": f"解密失敗：密碼/金鑰不正確或檔案已損壞 (GCM 認證失敗)。{str(e)}"}
    except FileNotFoundError:
        return {"status": "error", "message": "file_not_found", "details": file_path}
    except Exception as e:
        return {"status": "error", "message": "write_delete_failed", "details": str(e)}

    log_action(log_method, original_path, key_identifier_for_log)
    return {"status": "success", "original_path": original_path, 
            "method": "password" if password else "keyfile", 
            "original_hash": extracted_hash.hex()}

# 輔助函式，用於取得資源路徑 (例如圖標)
def get_resource_path(relative_path):
    """取得資源檔的絕對路徑，兼容 PyInstaller 打包。"""
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

# ====== PyQt6 GUI 應用程式 ======
class CryptoApp(QWidget):
    def __init__(self):
        super().__init__()
        self.current_mode = "encrypt" # "encrypt" or "decrypt"
        self.use_password_mode = False # 新增變數，標記是否使用密碼加密/解密
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("加密 / 解密工具")
        self.setFixedSize(650, 550) # 固定視窗大小
        
        # 設定視窗圖標 (需要有 img/LOGO.ico 檔案)
        icon_path = get_resource_path('img/LOGO.ico')
        if os.path.exists(icon_path):
            icon = QIcon()
            icon.addPixmap(QIcon(icon_path).pixmap(QSize(256, 256)), QIcon.Mode.Normal, QIcon.State.Off)
            self.setWindowIcon(icon)
        else:
            print(f"Warning: Icon file not found at {icon_path}")

        # === 全局樣式 ===
        self.setStyleSheet("""
            QWidget {
                background-color: #2e3440; /* Nord0 */
                color: #eceff4; /* Nord6 */
                font-family: 'Microsoft JhengHei UI', 'Segoe UI', sans-serif;
                font-size: 12pt;
            }
            QPushButton {
                background-color: #3b4252; /* Nord1 */
                border-radius: 8px;
                color: #eceff4; /* Nord6 */
                font-size: 16pt;
                padding: 8px 15px;
            }
            QPushButton:hover {
                background-color: #5e81ac; /* Nord9 (light blue) */
            }
            QPushButton:pressed {
                background-color: #88c0d0; /* Nord8 (darker light blue) */
            }
            QPushButton:disabled {
                background-color: #4c566a; /* Nord3 */
                color: #d8dee9; /* Nord4 */
            }
            #encryptButton:disabled {
                background-color: #bf616a; /* Nord11 - 偏紅色系作為加密模式被選中 */
                color: #eceff4; /* 亮色文字 */
                border: 2px solid #b48ead;
            }
            #decryptButton:disabled {
                background-color: #a3be8c; /* Nord14 - 偏綠色系作為解密模式被選中 */
                color: #2e3440; /* 深色文字，與淺綠色背景對比 */
                border: 2px solid #8fbcbb;
            }
            QLineEdit {
                background-color: #4c566a; /* Nord3 */
                border: 1px solid #3b4252; /* Nord1 */
                border-radius: 5px;
                padding: 5px;
                color: #eceff4; /* Nord6 */
            }
            QLineEdit:hover {
                border: 1px solid #88c0d0; /* Nord8 */
            }
            QLineEdit:focus {
                border: 1px solid #81a1c1; /* Nord7 */
            }
            QLineEdit[dragging="true"] { 
                background-color: #434c5e; 
                border: 2px dashed #88c0d0; 
            } /* 拖曳時的樣式 */
            QTextEdit {
                background-color: #3b4252; /* Nord1 */
                border: 1px solid #4c566a; /* Nord3 */
                border-radius: 5px;
                padding: 5px;
                color: #eceff4; /* Nord6 */
            }
            QTextEdit QScrollBar:vertical {
                border: none;
                background-color: #4c566a; /* Nord3 */
                width: 12px;
                margin: 0;
            }
            QTextEdit QScrollBar::handle:vertical {
                background-color: #88c0d0; /* Nord8 */
                min-height: 20px;
                border-radius: 5px;
            }
            QTextEdit QScrollBar::add-line:vertical,
            QTextEdit QScrollBar::sub-line:vertical {
                border: none;
                background: none;
                height: 0;
            }
            QTextEdit QScrollBar::add-page:vertical,
            QTextEdit QScrollBar::sub-page:vertical {
                background: none;
            }
            QToolTip { 
                background-color: #eceff4; /* Nord6 */
                color: black; 
                border: 1px solid #d8dee9; /* Nord4 */
                border-radius: 3px;
                padding: 3px;
                font-size: 10pt;
            }
            QCheckBox {
                spacing: 7px;
                color: #eceff4; /* Nord6 */
                font-size: 12pt;
            }
            QCheckBox::indicator {
                width: 20px;
                height: 20px;
                border: 2px solid #5e81ac; /* Nord9 - 邊框顏色 */
                border-radius: 6px; /* 圓角 */
                background-color: #3b4252; /* Nord1 - 預設背景色 */
            }
            QCheckBox::indicator:unchecked {
                background-color: #3b4252; /* Nord1 - 未選中時背景色 */
                border: 2px solid #5e81ac; /* Nord9 - 未選中時邊框顏色 */
            }
            QCheckBox::indicator:unchecked:hover {
                border: 2px solid #88c0d0; /* Nord8 - 未選中懸停時邊框顏色 */
            }
            QCheckBox::indicator:checked {
                background-color: #5e81ac; /* Nord9 - 選中時背景色 */
                border: 2px solid #5e81ac; /* Nord9 - 選中時邊框顏色 */
            }
            QCheckBox::indicator:checked:hover {
                background-color: #1f5fad; /* Nord14 - 選中懸停時背景色 */
                border: 2px solid #5e81ac; /* Nord14 - 選中懸停時邊框顏色 */
            }
            QCheckBox:disabled {
                color: #4c566a; /* Nord3 - 禁用時文字顏色 */
            }
            QCheckBox::indicator:disabled {
                background-color: #2e3440; /* Nord0 - 禁用時方框背景色 */
                border: 2px solid #4c566a; /* Nord3 - 禁用時方框邊框顏色 */
            }
        """)

        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(10, 10, 10, 10) # 設定邊距
        main_layout.setSpacing(10) # 設定元件間距

        # 模式選擇區
        mode_layout = QHBoxLayout()
        self.encrypt_button = QPushButton("加密")
        self.decrypt_button = QPushButton("解密")
        self.encrypt_button.setObjectName("encryptButton")
        self.decrypt_button.setObjectName("decryptButton")
        self.encrypt_button.clicked.connect(self.set_encrypt_mode)
        self.decrypt_button.clicked.connect(self.set_decrypt_mode)
        mode_btn_font = QFont("Segoe UI", 14, QFont.Weight.Bold) 
        
        self.encrypt_button.setFont(mode_btn_font)
        self.decrypt_button.setFont(mode_btn_font)

        mode_layout.addWidget(self.encrypt_button)
        mode_layout.addWidget(self.decrypt_button)
        main_layout.addLayout(mode_layout)

        # 檔案操作區 (支援拖曳)
        file_layout = QHBoxLayout()
        self.file_path_label = QLabel("檔案路徑:")
        self.file_path_label.setFixedWidth(80) # 固定標籤寬度
        
        self.file_path_input = QLineEdit()
        self.file_path_input.setPlaceholderText("點擊選擇檔案或拖曳檔案至此")
        self.file_path_input.setReadOnly(True)
        self.file_path_input.mousePressEvent = self.open_file_dialog
        self.file_path_input.setAcceptDrops(True)
        self.file_path_input.dragEnterEvent = self.drag_enter_event
        self.file_path_input.dropEvent = self.drop_event
        self.file_path_input.setProperty("dragging", False) # 初始屬性

        file_layout.addWidget(self.file_path_label)
        file_layout.addWidget(self.file_path_input)
        main_layout.addLayout(file_layout)

        # 新增：使用密碼加密/解密勾選框
        self.use_password_checkbox = QCheckBox("使用自定義密碼")
        self.use_password_checkbox.stateChanged.connect(self.update_key_input_mode)
        main_layout.addWidget(self.use_password_checkbox)

        # 金鑰/密碼輸入區
        key_password_layout = QHBoxLayout()
        self.key_password_label = QLabel("金鑰路徑:") # 預設為金鑰路徑
        self.key_password_label.setFixedWidth(80) 

        self.key_password_input = QLineEdit()
        self.key_password_input.setPlaceholderText("選填：手動指定金鑰檔案 (.key)")
        # 初始設定為金鑰檔案模式的拖曳屬性
        self.key_password_input.setAcceptDrops(True)
        self.key_password_input.dragEnterEvent = self.drag_enter_event
        self.key_password_input.dropEvent = self.drop_key_event
        self.key_password_input.mousePressEvent = self.open_key_dialog
        self.key_password_input.setProperty("dragging", False) # 初始屬性
        self.key_password_input.setReadOnly(True) # 預設為只讀

        key_password_layout.addWidget(self.key_password_label)
        key_password_layout.addWidget(self.key_password_input)
        main_layout.addLayout(key_password_layout)

        # 訊息輸出區
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        main_layout.addWidget(self.log_output)
        
        # 執行按鈕
        self.execute_button = QPushButton("執行")
        self.execute_button.clicked.connect(self.execute_action)
        execute_btn_font = QFont("Segoe UI", 14, QFont.Weight.Bold)
        self.execute_button.setFont(execute_btn_font)
        main_layout.addWidget(self.execute_button)

        self.setLayout(main_layout)
        self.set_encrypt_mode() # 初始設定為加密模式
        self.update_key_input_mode() # 初始化金鑰/密碼輸入框狀態

    def set_encrypt_mode(self):
        """切換到加密模式。"""
        self.current_mode = "encrypt"
        self.encrypt_button.setEnabled(False)
        self.decrypt_button.setEnabled(True)
        self.execute_button.setText("執行加密")
        self.log_output.clear()
        self.output_message("已切換至 **加密模式**", "info", icon="ℹ️")
        self.file_path_input.clear()
        self.key_password_input.clear()
        self.update_key_input_mode() # 根據密碼模式更新輸入框狀態

    def set_decrypt_mode(self):
        """切換到解密模式。"""
        self.current_mode = "decrypt"
        self.encrypt_button.setEnabled(True)
        self.decrypt_button.setEnabled(False)
        self.execute_button.setText("執行解密")
        self.log_output.clear()
        self.output_message("已切換至 **解密模式**", "info", icon="ℹ️")
        self.file_path_input.clear()
        self.key_password_input.clear()
        self.update_key_input_mode() # 根據密碼模式更新輸入框狀態

    def update_key_input_mode(self):
        """根據 '使用自定義密碼' 勾選框的狀態更新金鑰/密碼輸入框。"""
        self.use_password_mode = self.use_password_checkbox.isChecked()
        self.key_password_input.clear() # 清空輸入框內容

        if self.use_password_mode:
            self.key_password_label.setText("自訂密碼:")
            self.key_password_input.setPlaceholderText("輸入自定義密碼")
            self.key_password_input.setEchoMode(QLineEdit.EchoMode.Password) # 隱藏密碼
            self.key_password_input.setReadOnly(False) # 可編輯
            self.key_password_input.setAcceptDrops(False) # 禁用拖曳
            # 覆蓋 mousePressEvent，防止點擊時彈出檔案對話框
            self.key_password_input.mousePressEvent = lambda event: None 
        else:
            self.key_password_label.setText("金鑰路徑:")
            self.key_password_input.setPlaceholderText("選填：手動指定金鑰檔案 (.key)")
            self.key_password_input.setEchoMode(QLineEdit.EchoMode.Normal) # 正常顯示
            self.key_password_input.setReadOnly(True) # 只讀
            self.key_password_input.setAcceptDrops(True) # 啟用拖曳
            # 恢復 mousePressEvent 為開啟檔案對話框
            self.key_password_input.mousePressEvent = self.open_key_dialog

    def open_file_dialog(self, event):
        """開啟檔案選擇對話框，用於選擇要加密/解密的檔案。"""
        if event.button() == Qt.MouseButton.LeftButton:
            file_path, _ = QFileDialog.getOpenFileName(self, "選擇檔案")
            if file_path:
                self.file_path_input.setText(file_path)

    def open_key_dialog(self, event):
        """
        開啟金鑰檔案選擇對話框，僅在非密碼模式下啟用。
        """
        if not self.use_password_mode and event.button() == Qt.MouseButton.LeftButton:
            key_path, _ = QFileDialog.getOpenFileName(self, "選擇金鑰檔案", filter="Key Files (*.key)")
            if key_path:
                self.key_password_input.setText(key_path)

    def drag_enter_event(self, event):
        """處理拖曳進入事件，為拖曳的輸入框添加視覺提示。"""
        if event.mimeData().hasUrls():
            sender_input = self.sender()
            if isinstance(sender_input, QLineEdit):
                sender_input.setProperty("dragging", True)
                sender_input.style().polish(sender_input) # 更新樣式
            event.accept()
        else:
            event.ignore()
    
    def drag_leave_event(self, event):
        """處理拖曳離開事件，移除拖曳的輸入框的視覺提示。"""
        sender_input = self.sender()
        if isinstance(sender_input, QLineEdit):
            sender_input.setProperty("dragging", False)
            sender_input.style().polish(sender_input) # 更新樣式
        event.accept()

    def drop_event(self, event):
        """處理檔案拖曳釋放事件，設定檔案路徑。"""
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()
            self.file_path_input.setText(file_path)
            # 移除拖曳視覺提示
            self.file_path_input.setProperty("dragging", False)
            self.file_path_input.style().polish(self.file_path_input)
            event.accept()
        else:
            event.ignore()
    
    def drop_key_event(self, event):
        """
        處理金鑰檔案拖曳釋放事件，僅在非密碼模式下接受 .key 檔案。
        """
        if not self.use_password_mode:
            urls = event.mimeData().urls()
            if urls:
                key_path = urls[0].toLocalFile()
                if key_path.lower().endswith('.key'): # 僅接受 .key 檔案 (忽略大小寫)
                    self.key_password_input.setText(key_path)
                    # 移除拖曳視覺提示
                    self.key_password_input.setProperty("dragging", False)
                    self.key_password_input.style().polish(self.key_password_input)
                    event.accept()
                else:
                    self.output_message("❌ 請拖曳有效的金鑰檔案 (.key 檔)。", "error")
                    # 移除拖曳視覺提示
                    self.key_password_input.setProperty("dragging", False)
                    self.key_password_input.style().polish(self.key_password_input)
                    event.ignore()
            else:
                event.ignore()
        else: # 密碼模式下不接受拖曳
            event.ignore()


    def output_message(self, message: str, msg_type: str = "info", indent: int = 0, icon: str = ""):
        """
        在 QTextEdit 中輸出帶有樣式的訊息。
        支援 info, success, warning, error 四種類型。
        """
        color_map = {
            "info": "#eceff4",    # Nord6 (light gray)
            "success": "#a3be8c", # Nord14 (green)
            "warning": "#ebcb8b", # Nord12 (yellow)
            "error": "#bf616a"    # Nord11 (red)
        }
        color = color_map.get(msg_type, "#eceff4")
        
        indent_str = "&nbsp;" * 4 * indent # 每個縮排級別使用 4 個半形空格

        # 將 Markdown 的 ** 和 ` 替換為 HTML 標籤
        message = message.replace('**', '<strong>').replace('`', '') 

        # 組合帶有圖示和縮排的訊息
        final_message = f"{indent_str}<span style='color:{color};'>{icon} {message}</span>"
        if msg_type in ["success", "error", "warning"]:
            # 對於成功、錯誤、警告訊息，加粗整個訊息內容
            final_message = f"{indent_str}<span style='color:{color}; font-weight:bold;'>{icon} {message}</span>"
        
        self.log_output.append(final_message)
        self.log_output.verticalScrollBar().setValue(self.log_output.verticalScrollBar().maximum())

    def execute_action(self,):
        """根據當前模式執行加密或解密操作。"""
        self.log_output.append("<span style='color: #84abab;'>------------------------------------------------------------------------------------</span>") 

        file_path = self.file_path_input.text()
        if not file_path:
            self.output_message("請選擇或拖曳一個檔案。", "error", icon="❌")
            return

        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        display_mode = ""
        action_type = ""
        if self.current_mode == "encrypt":
            display_mode = "加密"
            action_type = "encrypt"
        elif self.current_mode == "decrypt":
            display_mode = "解密"
            action_type = "decrypt"

        self.output_message(f"[{timestamp}] 執行模式： {display_mode}", "info", icon="▶️")
        
        password_input = self.key_password_input.text() if self.use_password_mode else None
        key_file_input = self.key_password_input.text() if not self.use_password_mode else ""

        if action_type == "encrypt":
            if self.use_password_mode:
                if not password_input:
                    self.output_message("請輸入用於加密的密碼。", "error", icon="❌")
                    return
                self.output_message(f"嘗試使用密碼加密檔案：`{os.path.basename(file_path)}`", "info", indent=1, icon="🔒")
            else:
                self.output_message(f"嘗試使用隨機金鑰加密檔案：`{os.path.basename(file_path)}`", "info", indent=1, icon="🔒")

            encrypt_result = encrypt_file_logic(file_path, password=password_input)

            if encrypt_result["status"] == "success":
                self.output_message(f"檔案加密完成：`{os.path.basename(encrypt_result['encrypted_path'])}`", "success", indent=1, icon="✅")
                self.output_message(f"原始檔案內容雜湊值 (HEX)：`{encrypt_result['original_hash']}`", "info", indent=1, icon="🆔")
                if encrypt_result["method"] == "keyfile":
                    self.output_message(f"金鑰檔已儲存於：`{os.path.basename(encrypt_result['key_path'])}`", "info", indent=1, icon="🔑")
                else: # password method
                    self.output_message("已使用密碼加密，無需單獨儲存金鑰檔。", "info", indent=1, icon="🔑")
                self.file_path_input.clear()
            elif encrypt_result["status"] == "partial_success":
                self.output_message(f"檔案加密完成：`{os.path.basename(encrypt_result['encrypted_path'])}`", "success", indent=1, icon="✅")
                self.output_message(f"原始檔案內容雜湊值 (HEX)：`{encrypt_result['original_hash']}`", "info", indent=1, icon="🆔")
                self.output_message(f"金鑰儲存失敗：{encrypt_result['details']} (嘗試金鑰檔名: `{os.path.basename(encrypt_result['key_path_attempted'])}`)", "warning", indent=1, icon="⚠️")
                self.output_message("加密操作部分完成，請手動備份金鑰！", "warning", indent=0, icon="⚠️")
                self.file_path_input.clear()
            elif encrypt_result["status"] == "warning":
                self.output_message(f"檔案似乎已加密，跳過加密。", "warning", indent=1, icon="⚠️")
                self.output_message("加密操作已跳過。", "info", indent=0, icon="ℹ️")
                self.file_path_input.clear()
            else: # error 狀態
                error_type = encrypt_result["message"]
                if error_type == "file_not_found":
                    self.output_message(f"找不到檔案：`{encrypt_result['details']}`", "error", indent=1, icon="❌")
                elif error_type == "file_read_error":
                    self.output_message(f"讀取檔案時發生錯誤：`{encrypt_result['details']}`", "error", indent=1, icon="❌")
                elif error_type == "encryption_failed":
                    self.output_message(f"加密失敗：`{encrypt_result['details']}`", "error", indent=1, icon="❌")
                elif error_type == "write_delete_failed":
                    self.output_message(f"寫入加密檔案或刪除原始檔案失敗：`{encrypt_result['details']}`", "error", indent=1, icon="❌")
                self.output_message("加密操作失敗。", "error", indent=0, icon="🚫")
                self.file_path_input.clear()

        elif action_type == "decrypt":
            if self.use_password_mode:
                if not password_input:
                    self.output_message("請輸入用於解密的密碼。", "error", icon="❌")
                    return
                self.output_message(f"嘗試使用密碼解密檔案：`{os.path.basename(file_path)}`", "info", indent=1, icon="🔓")
            else:
                self.output_message(f"嘗試使用金鑰檔解密檔案：`{os.path.basename(file_path)}`", "info", indent=1, icon="🔓")
                if key_file_input:
                    self.output_message(f"使用指定金鑰：`{os.path.basename(key_file_input)}`", "info", indent=1, icon="🔑")
                else:
                    self.output_message(f"將自動嘗試從加密檔中提取雜湊值，並查找 `{KEY_FOLDER}` 資料夾下的對應金鑰檔。", "info", indent=1, icon="🔑")

            decrypt_result = decrypt_file_logic(file_path, key_path_input=key_file_input, password=password_input)

            if decrypt_result["status"] == "success":
                self.output_message(f"解密完成，還原檔案：`{os.path.basename(decrypt_result['original_path'])}`", "success", indent=1, icon="✅")
                self.output_message(f"原始檔案內容雜湊值 (HEX)：`{decrypt_result['original_hash']}`", "info", indent=1, icon="🆔")
                self.file_path_input.clear()
                self.key_password_input.clear()
            else: # error 狀態
                error_type = decrypt_result["message"]
                if error_type == "not_encrypted_file":
                    self.output_message("錯誤：此檔案不是加密檔案（缺少 .bwpsen 副檔名）。", "error", indent=1, icon="❌")
                elif error_type == "key_not_found_for_keyfile":
                    self.output_message("錯誤：無法找到金鑰檔案。請確認金鑰存在或手動指定。", "error", indent=1, icon="❌")
                elif error_type == "key_file_read_error": # 新增的金鑰檔案讀取錯誤
                     self.output_message(f"錯誤：讀取金鑰檔案時發生錯誤：`{decrypt_result['details']}`", "error", indent=1, icon="❌")
                elif error_type == "invalid_encrypted_file_format":
                    self.output_message(f"錯誤：檔案格式不正確，可能與所選解密模式不符或已損壞。", "error", indent=1, icon="❌")
                    if "details" in decrypt_result:
                        self.output_message(f"詳細錯誤: {decrypt_result['details']}", "error", indent=2, icon="ℹ️")
                elif error_type == "decryption_failed":
                    self.output_message(f"解密失敗：`{decrypt_result['details']}`", "error", indent=1, icon="❌")
                    self.output_message("請檢查密碼或金鑰是否正確，或檔案是否損壞。", "warning", indent=2, icon="⚠️")
                elif error_type == "write_delete_failed":
                    self.output_message(f"寫入解密檔案或刪除原始加密檔案失敗：`{decrypt_result['details']}`", "error", indent=1, icon="❌")
                self.output_message("解密操作失敗。", "error", indent=0, icon="🚫")
                self.file_path_input.clear()
                self.key_password_input.clear()

        self.log_output.verticalScrollBar().setValue(self.log_output.verticalScrollBar().maximum())


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CryptoApp()
    window.show()
    sys.exit(app.exec())
