import os
import sys
import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QLineEdit, QTextEdit, QFileDialog, QMessageBox
)
from PyQt6.QtCore import Qt, QMimeData, QUrl, QSize
from PyQt6.QtGui import QIcon, QFont, QColor, QPalette

# ====== 設定變數 ======
SUFFIX = '.bwpsen'
KEY_FOLDER = 'Key'
LOG_FILE = 'Encryption_Tools_Log.txt'

# ====== 工具函式 ======
def get_base_dir():
    if getattr(sys, 'frozen', False):  # PyInstaller 打包執行
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def get_key_dir():
    path = os.path.join(get_base_dir(), KEY_FOLDER)
    os.makedirs(path, exist_ok=True)
    return path

def log_action(action: str, filepath: str):
    full_path = os.path.abspath(filepath)
    size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    log_line = f"[{timestamp}] {action.upper()} | {os.path.basename(filepath)} | {full_path} | {size} bytes\n"
    with open(os.path.join(get_base_dir(), LOG_FILE), 'a', encoding='utf-8') as f:
        f.write(log_line)

# ====== 加解密功能 ======
def generate_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)

def encrypt_file_logic(file_path: str): # 不再傳入 log_output_func
    if file_path.endswith(SUFFIX):
        return {"status": "warning", "message": "file_already_encrypted"}

    key = generate_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)

    try:
        with open(file_path, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        return {"status": "error", "message": "file_not_found", "details": file_path}
    except Exception as e:
        return {"status": "error", "message": "file_read_error", "details": str(e)}

    try:
        encrypted_data = aesgcm.encrypt(nonce, data, None)
    except Exception as e:
        return {"status": "error", "message": "encryption_failed", "details": str(e)}

    encrypted_path = file_path + SUFFIX
    try:
        with open(encrypted_path, 'wb') as f:
            f.write(nonce + encrypted_data)
        os.remove(file_path) # 成功加密後刪除原始檔案
    except Exception as e:
        return {"status": "error", "message": "write_delete_failed", "details": str(e)}

    key_filename = os.path.basename(file_path) + '.key'
    key_path = os.path.join(get_key_dir(), key_filename)
    try:
        with open(key_path, 'wb') as f:
            f.write(key)
    except Exception as e:
        log_action('encrypt_partial_success', encrypted_path) # 即使金鑰儲存失敗，加密仍成功
        return {"status": "partial_success", "message": "key_save_failed", "details": str(e),
                "encrypted_path": encrypted_path, "key_path_attempted": key_path}

    log_action('encrypt', encrypted_path)
    return {"status": "success", "encrypted_path": encrypted_path, "key_path": key_path}


def decrypt_file_logic(file_path: str, key_path_input: str): # 不再傳入 log_output_func
    if not file_path.endswith(SUFFIX):
        return {"status": "error", "message": "not_encrypted_file"}

    original_path = file_path[:-len(SUFFIX)]
    default_key_filename = os.path.basename(original_path) + '.key'
    default_key_path = os.path.join(get_key_dir(), default_key_filename)

    key_to_use = ""
    if key_path_input:
        key_to_use = key_path_input
    elif os.path.exists(default_key_path):
        key_to_use = default_key_path
    else:
        return {"status": "error", "message": "key_not_found"}

    # 內部函式，用於嘗試解密並返回結果和可能的錯誤
    def try_decrypt(key_path_param):
        try:
            with open(key_path_param, 'rb') as f:
                key = f.read()

            with open(file_path, 'rb') as f:
                content = f.read()
                nonce = content[:12]
                encrypted_data = content[12:]

            aesgcm = AESGCM(key)
            decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
            return {"status": "success", "data": decrypted_data, "key_path": key_path_param}
        except Exception as e:
            return {"status": "failed", "key_path": key_path_param, "error_detail": str(e)}

    # 執行解密嘗試
    decryption_attempt = try_decrypt(key_to_use)

    if decryption_attempt["status"] == "failed":
        # 返回解密嘗試失敗的具體資訊
        return {"status": "error", "message": "decryption_failed", "details": decryption_attempt}

    decrypted_data = decryption_attempt["data"]

    try:
        with open(original_path, 'wb') as f:
            f.write(decrypted_data)
        os.remove(file_path)
    except Exception as e:
        return {"status": "error", "message": "write_delete_failed", "details": str(e)}

    log_action('decrypt', original_path)
    return {"status": "success", "original_path": original_path}

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
        self.current_mode = "encrypt"
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
        
        # 調整按鈕字體大小，保持風格一致
        self.encrypt_button.setFont(mode_btn_font)
        self.decrypt_button.setFont(mode_btn_font)

        self.encrypt_button.clicked.connect(self.set_encrypt_mode)
        self.decrypt_button.clicked.connect(self.set_decrypt_mode)
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
        
        # 增加拖曳視覺提示
        self.file_path_input.setStyleSheet(self.file_path_input.styleSheet() + """
            QLineEdit:hover { border: 1px solid #88c0d0; }
            QLineEdit[dragging="true"] { background-color: #434c5e; border: 2px dashed #88c0d0; } /* 拖曳時的樣式 */
        """)
        self.file_path_input.setProperty("dragging", False) # 初始屬性

        file_layout.addWidget(self.file_path_label)
        file_layout.addWidget(self.file_path_input)
        main_layout.addLayout(file_layout)

        # 金鑰輸入區 (預設隱藏，解密時顯示)
        key_layout = QHBoxLayout()
        self.key_path_label = QLabel("金鑰路徑:")
        self.key_path_label.setFixedWidth(80) # 固定標籤寬度

        self.key_path_input = QLineEdit()
        self.key_path_input.setPlaceholderText("選填：手動指定金鑰檔案 (.key)")
        self.key_path_input.setAcceptDrops(True)
        self.key_path_input.dragEnterEvent = self.drag_enter_event
        self.key_path_input.dropEvent = self.drop_key_event
        self.key_path_input.mousePressEvent = self.open_key_dialog
        
        # 增加拖曳視覺提示
        self.key_path_input.setStyleSheet(self.key_path_input.styleSheet() + """
            QLineEdit:hover { border: 1px solid #88c0d0; }
            QLineEdit[dragging="true"] { background-color: #434c5e; border: 2px dashed #88c0d0; } /* 拖曳時的樣式 */
        """)
        self.key_path_input.setProperty("dragging", False) # 初始屬性


        key_layout.addWidget(self.key_path_label)
        key_layout.addWidget(self.key_path_input)
        main_layout.addLayout(key_layout)
        self.key_path_label.hide()
        self.key_path_input.hide()

        # 訊息輸出區
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        main_layout.addWidget(self.log_output)
        
        # 執行按鈕
        self.execute_button = QPushButton("執行")
        self.execute_button.clicked.connect(self.execute_action)
        execute_btn_font = QFont("Segoe UI", 14, QFont.Weight.Bold) # 調整字體大小和粗細
        self.execute_button.setFont(execute_btn_font)
        main_layout.addWidget(self.execute_button)

        self.setLayout(main_layout)
        self.set_encrypt_mode() # 初始設定為加密模式

    def set_encrypt_mode(self):
        self.current_mode = "encrypt"
        self.encrypt_button.setEnabled(False)
        self.decrypt_button.setEnabled(True)
        self.execute_button.setText("執行加密")
        self.key_path_label.hide()
        self.key_path_input.hide()
        self.key_path_input.clear()
        self.log_output.clear()
        self.output_message("已切換至 **加密模式**", "info", icon="ℹ️") # 使用圖示
        self.file_path_input.clear() # 清空檔案路徑輸入框

    def set_decrypt_mode(self):
        self.current_mode = "decrypt"
        self.encrypt_button.setEnabled(True)
        self.decrypt_button.setEnabled(False)
        self.execute_button.setText("執行解密")
        self.key_path_label.show()
        self.key_path_input.show()
        self.log_output.clear()
        self.output_message("已切換至 **解密模式**", "info", icon="ℹ️") # 使用圖示
        self.file_path_input.clear() # 清空檔案路徑輸入框

    def open_file_dialog(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            file_path, _ = QFileDialog.getOpenFileName(self, "選擇檔案")
            if file_path:
                self.file_path_input.setText(file_path)

    def open_key_dialog(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            key_path, _ = QFileDialog.getOpenFileName(self, "選擇金鑰檔案", filter="Key Files (*.key)")
            if key_path:
                self.key_path_input.setText(key_path)

    def drag_enter_event(self, event):
        if event.mimeData().hasUrls():
            sender_input = self.sender()
            if isinstance(sender_input, QLineEdit):
                sender_input.setProperty("dragging", True)
                sender_input.style().polish(sender_input) # 更新樣式
            event.accept()
        else:
            event.ignore()
    
    def drag_leave_event(self, event):
        sender_input = self.sender()
        if isinstance(sender_input, QLineEdit):
            sender_input.setProperty("dragging", False)
            sender_input.style().polish(sender_input) # 更新樣式
        event.accept()

    def drop_event(self, event):
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
        urls = event.mimeData().urls()
        if urls:
            key_path = urls[0].toLocalFile()
            if key_path.lower().endswith('.key'): # 僅接受 .key 檔案 (忽略大小寫)
                self.key_path_input.setText(key_path)
                # 移除拖曳視覺提示
                self.key_path_input.setProperty("dragging", False)
                self.key_path_input.style().polish(self.key_path_input)
                event.accept()
            else:
                self.output_message("❌ 請拖曳有效的金鑰檔案 (.key 檔)。", "error")
                # 移除拖曳視覺提示
                self.key_path_input.setProperty("dragging", False)
                self.key_path_input.style().polish(self.key_path_input)
                event.ignore()
        else:
            event.ignore()

    # 修改 output_message 函式，增加 icon 和 indent 參數
    def output_message(self, message: str, msg_type: str = "info", indent: int = 0, icon: str = ""):
        color_map = {
            "info": "#eceff4",    # Nord6 (light gray)
            "success": "#a3be8c", # Nord14 (green)
            "warning": "#ebcb8b", # Nord12 (yellow)
            "error": "#bf616a"    # Nord11 (red)
        }
        color = color_map.get(msg_type, "#eceff4")
        
        # 根據 indent 參數添加 HTML 縮排
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

    # 主要執行動作的函式
    def execute_action(self):

        self.log_output.append("<span style='color: #84abab;'>------------------------------------------------------------------------------------</span>") 

        file_path = self.file_path_input.text()
        if not file_path:
            self.output_message("請選擇或拖曳一個檔案。", "error", icon="❌")
            return

        # 在每次新操作開始前，新增一個分隔線和時間戳
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        display_mode = ""
        if self.current_mode == "encrypt":
            display_mode = "加密"
        elif self.current_mode == "decrypt":
            display_mode = "解密"

        self.output_message(f"[{timestamp}] 執行模式： {display_mode}", "info", icon="▶️")

        if self.current_mode == "encrypt":
            self.output_message(f"嘗試加密檔案：{os.path.basename(file_path)}", "info", indent=1, icon="📂")
            encrypt_result = encrypt_file_logic(file_path) # 呼叫加密邏輯

            if encrypt_result["status"] == "success":
                self.output_message(f"檔案加密完成：{os.path.basename(encrypt_result['encrypted_path'])}", "success", indent=1, icon="✅")
                self.output_message(f"金鑰已儲存於：{os.path.basename(encrypt_result['key_path'])}", "info", indent=1, icon="🔑")
                # self.output_message("加密操作完成！", "success", indent=0, icon="🎉")
                self.file_path_input.clear()
            elif encrypt_result["status"] == "partial_success":
                self.output_message(f"檔案加密完成：{os.path.basename(encrypt_result['encrypted_path'])}", "success", indent=1, icon="✅")
                self.output_message(f"金鑰儲存失敗：{encrypt_result['details']} (嘗試金鑰: {os.path.basename(encrypt_result['key_path_attempted'])})", "warning", indent=1, icon="⚠️")
                self.output_message("加密操作部分完成，請手動備份金鑰！", "warning", indent=0, icon="⚠️")
                self.file_path_input.clear()
            elif encrypt_result["status"] == "warning":
                self.output_message(f"檔案似乎已加密，跳過加密。", "warning", indent=1, icon="⚠️")
                self.output_message("加密操作已跳過。", "info", indent=0, icon="ℹ️")
                self.file_path_input.clear()
            else: # error 狀態
                error_type = encrypt_result["message"]
                if error_type == "file_not_found":
                    self.output_message(f"找不到檔案：{encrypt_result['details']}", "error", indent=1, icon="❌")
                elif error_type == "file_read_error":
                    self.output_message(f"讀取檔案時發生錯誤：{encrypt_result['details']}", "error", indent=1, icon="❌")
                elif error_type == "encryption_failed":
                    self.output_message(f"加密失敗：{encrypt_result['details']}", "error", indent=1, icon="❌")
                elif error_type == "write_delete_failed":
                    self.output_message(f"寫入加密檔案或刪除原始檔案失敗：{encrypt_result['details']}", "error", indent=1, icon="❌")
                self.output_message("加密操作失敗。", "error", indent=0, icon="🚫")
                self.file_path_input.clear()

        elif self.current_mode == "decrypt":
            key_path = self.key_path_input.text()
            
            self.output_message(f"嘗試解密檔案：{os.path.basename(file_path)}", "info", indent=1, icon="📂")
            if key_path:
                self.output_message(f"使用指定金鑰：{os.path.basename(key_path)}", "info", indent=1, icon="🔑")
            else:
                self.output_message(f"嘗試使用預設金鑰位置：{os.path.basename(file_path[:-len(SUFFIX)])}.key", "info", indent=1, icon="🔑")

            decrypt_result = decrypt_file_logic(file_path, key_path) # 呼叫解密邏輯

            if decrypt_result["status"] == "success":
                self.output_message(f"解密完成，還原檔案：{os.path.basename(decrypt_result['original_path'])}", "success", indent=1, icon="✅")
                # self.output_message("解密操作完成！", "success", indent=0, icon="🎉")
                self.file_path_input.clear()
                self.key_path_input.clear()
            else: # error 狀態
                error_type = decrypt_result["message"]
                if error_type == "not_encrypted_file":
                    self.output_message("錯誤：此檔案不是加密檔案（缺少 .bwpsen 副檔名）。", "error", indent=1, icon="❌")
                elif error_type == "key_not_found":
                    self.output_message("錯誤：無法找到金鑰檔案。請確認金鑰存在或手動指定。", "error", indent=1, icon="❌")
                elif error_type == "decryption_failed":
                    details = decrypt_result["details"]
                    self.output_message(f"解密嘗試失敗 (金鑰: {os.path.basename(details['key_path'])}): {details['error_detail']}", "error", indent=1, icon="❌")
                    self.output_message("請檢查金鑰是否正確或檔案是否損壞。", "warning", indent=2, icon="⚠️") # 更深一層縮排
                elif error_type == "write_delete_failed":
                    self.output_message(f"寫入解密檔案或刪除原始加密檔案失敗：{decrypt_result['details']}", "error", indent=1, icon="❌")
                self.output_message("解密操作失敗。", "error", indent=0, icon="🚫")
                self.file_path_input.clear()
                self.key_path_input.clear()

        self.log_output.verticalScrollBar().setValue(self.log_output.verticalScrollBar().maximum())


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CryptoApp()
    window.show()
    sys.exit(app.exec())