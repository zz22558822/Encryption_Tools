import os
import sys
import datetime
import regex as re
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtWidgets import QMessageBox, QMenu, QFileDialog, QRadioButton
from PyQt6.QtGui import QContextMenuEvent
from concurrent.futures import ThreadPoolExecutor

# ====== 設定變數 ======
# 加密檔案的副檔名
SUFFIX = '.bwpsen'
# 儲存金鑰的資料夾名稱
KEY_FOLDER = 'Key'
# 主要操作日誌檔案名稱
LOG_FILE = 'Encryption_Tools_Log.txt'
# 錯誤日誌檔案名稱
ERROR_LOG_FILE = 'Error_Log.txt'

# 取得資源路徑 (適用於PyInstaller打包的exe)
def get_resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

# UI介面設定類別
class Ui_Form(object):
    def setupUi(self, Form):
        # 設定視窗屬性
        Form.setObjectName("Form")
        Form.resize(520, 350) # 調整視窗高度以容納新元件
        Form.setMinimumSize(QtCore.QSize(520, 350))
        Form.setMaximumSize(QtCore.QSize(520, 350))
        # 設定視窗樣式 (背景色、文字顏色、字體、字體大小)
        Form.setStyleSheet("background-color: #2e3440; color: #eceff4; font-family: 'Microsoft JhengHei UI'; font-size: 12pt;")

        # 列表選單樣式 (用於顯示檔案路徑)
        self.listWidget = QtWidgets.QListWidget(parent=Form)
        self.listWidget.setGeometry(QtCore.QRect(10, 20, 500, 200))
        self.listWidget.setObjectName("listWidget")
        self.listWidget.setStyleSheet("""
            QScrollBar:vertical { border: none; background-color: #4c566a; width: 12px; margin: 0; }
            QScrollBar::handle:vertical { background-color: #88c0d0; min-height: 20px; border-radius: 5px; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { border: none; background: none; height: 0; }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: none; }
            QScrollBar:horizontal { border: none; background-color: #4c566a; height: 12px; margin: 0; }
            QScrollBar::handle:horizontal { background-color: #88c0d0; min-width: 20px; border-radius: 5px; }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { border: none; background: none; width: 0; }
            QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal { background: none; }
            QListWidget { background-color: #3b4252; border: 1px solid #4c566a; color: #eceff4; selection-background-color: #5e81ac; }
        """)

        # 進度條樣式
        self.progressBar = QtWidgets.QProgressBar(parent=Form)
        self.progressBar.setGeometry(QtCore.QRect(10, 230, 500, 23))
        self.progressBar.setProperty("value", 0)
        self.progressBar.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.progressBar.setTextVisible(True)
        self.progressBar.setOrientation(QtCore.Qt.Orientation.Horizontal)
        self.progressBar.setTextDirection(QtWidgets.QProgressBar.Direction.TopToBottom)
        self.progressBar.setObjectName("progressBar")
        self.progressBar.setStyleSheet(
            "QProgressBar { border: 2px solid #4c566a; border-radius: 5px; text-align: center; }"
            "QProgressBar::chunk { background-color: #88c0d0; width: 20px; }"
        )

        # 按鈕通用樣式
        button_style = (
            "QPushButton { background-color: #3b4252; border-radius: 8px; color: #eceff4; font-size: 16pt; }"
            "QPushButton:hover { background-color: #5e81ac; }"
            "QPushButton:disabled { background-color: #4c566a; color: #d8dee9; }"
        )
        small_button_style = (
            "QPushButton { background-color: #3b4252; border-radius: 8px; color: #eceff4; font-size: 14pt; }" # Adjusted font size for smaller buttons
            "QPushButton:hover { background-color: #5e81ac; }"
            "QPushButton:disabled { background-color: #4c566a; color: #d8dee9; }"
        )

        # 選擇檔案按鈕
        self.pushButton_select = QtWidgets.QPushButton(parent=Form)
        self.pushButton_select.setGeometry(QtCore.QRect(10, 265, 70, 41))
        self.pushButton_select.setFont(QtGui.QFont("Microsoft JhengHei UI", 16))
        self.pushButton_select.setStyleSheet(small_button_style)
        self.pushButton_select.setText("📁")
        self.pushButton_select.setObjectName("pushButton_select")
        self.pushButton_select.setToolTip("選擇檔案")
        # 提示框樣式，使其可見
        self.pushButton_select.setStyleSheet(small_button_style + "QToolTip { color: black; background-color: white; border: 1px solid gray; border-radius: 5px; padding: 3px; }")


        # 刪除選擇按鈕
        self.pushButton_remove = QtWidgets.QPushButton(parent=Form)
        self.pushButton_remove.setGeometry(QtCore.QRect(100, 265, 70, 41))
        self.pushButton_remove.setFont(QtGui.QFont("Microsoft JhengHei UI", 16))
        self.pushButton_remove.setStyleSheet(small_button_style)
        self.pushButton_remove.setText("❌")
        self.pushButton_remove.setObjectName("pushButton_remove")
        self.pushButton_remove.setToolTip("刪除選擇")
        self.pushButton_remove.setStyleSheet(small_button_style + "QToolTip { color: black; background-color: white; border: 1px solid gray; border-radius: 5px; padding: 3px; }")

        # 操作模式選擇 (加密/解密)
        self.radio_encrypt = QRadioButton("加密", parent=Form)
        self.radio_encrypt.setGeometry(QtCore.QRect(10, 320, 80, 20))
        self.radio_encrypt.setObjectName("radio_encrypt")
        self.radio_encrypt.setChecked(True) # 預設為加密
        self.radio_encrypt.setStyleSheet("""
            QRadioButton { color: #eceff4; }
            QRadioButton::indicator { width: 15px; height: 15px; border-radius: 7px; background-color: #4c566a; border: 1px solid #d8dee9; }
            QRadioButton::indicator:checked { background-color: #88c0d0; border: 1px solid #88c0d0; }
        """)

        self.radio_decrypt = QRadioButton("解密", parent=Form)
        self.radio_decrypt.setGeometry(QtCore.QRect(100, 320, 80, 20))
        self.radio_decrypt.setObjectName("radio_decrypt")
        self.radio_decrypt.setStyleSheet("""
            QRadioButton { color: #eceff4; }
            QRadioButton::indicator { width: 15px; height: 15px; border-radius: 7px; background-color: #4c566a; border: 1px solid #d8dee9; }
            QRadioButton::indicator:checked { background-color: #88c0d0; border: 1px solid #88c0d0; }
        """)

        # 執行按鈕
        self.pushButton_execute = QtWidgets.QPushButton(parent=Form)
        self.pushButton_execute.setGeometry(QtCore.QRect(190, 265, 320, 41))
        self.pushButton_execute.setFont(QtGui.QFont("Segoe UI", 10, QtGui.QFont.Weight.Bold))
        self.pushButton_execute.setStyleSheet(button_style)
        self.pushButton_execute.setText("執 行")
        self.pushButton_execute.setObjectName("pushButton_execute")
        self.pushButton_execute.setToolTip("開始處理選定的檔案")
        self.pushButton_execute.setStyleSheet(button_style + "QToolTip { color: black; background-color: white; border: 1px solid gray; border-radius: 5px; padding: 3px; }")

        # 金鑰選擇按鈕 (解密模式下才顯示)
        self.pushButton_select_key = QtWidgets.QPushButton(parent=Form)
        self.pushButton_select_key.setGeometry(QtCore.QRect(190, 315, 120, 30))
        self.pushButton_select_key.setFont(QtGui.QFont("Microsoft JhengHei UI", 10))
        self.pushButton_select_key.setStyleSheet(small_button_style)
        self.pushButton_select_key.setText("選擇金鑰")
        self.pushButton_select_key.setObjectName("pushButton_select_key")
        self.pushButton_select_key.setToolTip("手動選擇解密金鑰檔案 (.key)")
        self.pushButton_select_key.setStyleSheet(small_button_style + "QToolTip { color: black; background-color: white; border: 1px solid gray; border-radius: 5px; padding: 3px; }")
        self.pushButton_select_key.setVisible(False) # 預設隱藏

        # 顯示金鑰路徑的標籤
        self.label_key_path = QtWidgets.QLabel("未選擇金鑰檔案", parent=Form)
        self.label_key_path.setGeometry(QtCore.QRect(320, 315, 190, 30))
        self.label_key_path.setAlignment(QtCore.Qt.AlignmentFlag.AlignVCenter | QtCore.Qt.AlignmentFlag.AlignLeft)
        self.label_key_path.setStyleSheet("color: #d8dee9; font-size: 10pt; background-color: #4c566a; border-radius: 5px; padding: 5px; border: 1px solid #4c566a;")
        self.label_key_path.setObjectName("label_key_path")
        self.label_key_path.setVisible(False) # 預設隱藏

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        # 設定視窗標題
        Form.setWindowTitle("文件加解密工具")

# 檔案處理邏輯類別
class FileProcessor(QtCore.QObject):
    # 訊號：進度條更新 (int: 進度百分比)
    progressUpdated = QtCore.pyqtSignal(int)
    # 訊號：處理完成 (int: 成功數量, int: 失敗數量, str: 錯誤日誌檔案路徑)
    processingFinished = QtCore.pyqtSignal(int, int, str)
    # 訊號：顯示訊息框 (str: 標題, str: 訊息內容)
    messageSignal = QtCore.pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.base_dir = self._get_base_dir()
        self.key_dir = self._get_key_dir()
        # 目前手動選擇的金鑰路徑，預設為None
        self.current_key_path = None

    def _get_base_dir(self):
        # 取得應用程式執行檔所在的路徑
        if getattr(sys, 'frozen', False):
            return os.path.dirname(sys.executable)
        return os.path.dirname(os.path.abspath(__file__))

    def _get_key_dir(self):
        # 建立金鑰儲存資料夾路徑，如果不存在則建立
        path = os.path.join(self.base_dir, KEY_FOLDER)
        os.makedirs(path, exist_ok=True)
        return path

    def _log_action(self, action: str, filepath: str, status: str = 'SUCCESS', message: str = ''):
        # 記錄操作日誌
        full_path = os.path.abspath(filepath)
        size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        log_line = f"[{timestamp}] {action.upper()} | {status} | {os.path.basename(filepath)} | {full_path} | {size} bytes"
        if message:
            log_line += f" | Message: {message}"
        log_line += "\n"

        with open(os.path.join(self.base_dir, LOG_FILE), 'a', encoding='utf-8') as f:
            f.write(log_line)

    def _generate_key(self) -> bytes:
        # 生成AESGCM金鑰 (256位元)
        return AESGCM.generate_key(bit_length=256)

    def _encrypt_file_internal(self, file_path: str) -> bool:
        # 內部加密檔案功能
        if file_path.endswith(SUFFIX):
            # 如果檔案已經是加密副檔名，則跳過加密
            self.messageSignal.emit("警告", f"⚠️ 檔案似乎已加密，跳過加密：{os.path.basename(file_path)}")
            self._log_action('encrypt', file_path, 'SKIPPED', 'File already encrypted')
            return False

        try:
            key = self._generate_key()
            aesgcm = AESGCM(key)
            nonce = os.urandom(12) # 隨機生成一次性數值

            with open(file_path, 'rb') as f:
                data = f.read()

            encrypted_data = aesgcm.encrypt(nonce, data, None)

            encrypted_path = file_path + SUFFIX
            with open(encrypted_path, 'wb') as f:
                f.write(nonce + encrypted_data) # 將nonce和加密資料寫入新檔案

            os.remove(file_path) # 刪除原始檔案

            key_filename = os.path.basename(file_path) + '.key'
            key_path = os.path.join(self.key_dir, key_filename)
            with open(key_path, 'wb') as f:
                f.write(key) # 儲存金鑰檔案

            self._log_action('encrypt', encrypted_path)
            self.messageSignal.emit("成功", f"✅ 檔案加密完成：{os.path.basename(encrypted_path)}\n🔑 金鑰已儲存於：{os.path.basename(key_path)}")
            return True
        except Exception as e:
            # 捕獲加密過程中的錯誤
            self._log_action('encrypt', file_path, 'FAILED', str(e))
            self.messageSignal.emit("錯誤", f"❌ 加密失敗：{os.path.basename(file_path)}\n錯誤：{str(e)}")
            return False

    def _decrypt_file_internal(self, file_path: str, provided_key_path: str = None) -> bool:
        # 內部解密檔案功能
        if not file_path.endswith(SUFFIX):
            # 如果檔案不是加密副檔名，則跳過解密
            self.messageSignal.emit("警告", f"❌ 此檔案不是加密檔案，跳過解密：{os.path.basename(file_path)}")
            self._log_action('decrypt', file_path, 'SKIPPED', 'Not an encrypted file')
            return False

        original_path = file_path[:-len(SUFFIX)]
        default_key_filename = os.path.basename(original_path) + '.key'
        default_key_path = os.path.join(self.key_dir, default_key_filename)

        decrypted_data = None

        def attempt_decryption(key_path):
            # 嘗試使用指定的金鑰進行解密
            try:
                with open(key_path, 'rb') as f:
                    key = f.read()
                
                with open(file_path, 'rb') as f:
                    content = f.read()
                    nonce = content[:12] # 前12位元組為nonce
                    encrypted_data = content[12:] # 剩餘為加密資料

                aesgcm = AESGCM(key)
                return aesgcm.decrypt(nonce, encrypted_data, None)
            except Exception:
                return None
        
        # 優先使用手動提供的金鑰進行解密
        if provided_key_path and os.path.exists(provided_key_path):
            decrypted_data = attempt_decryption(provided_key_path)
        
        # 如果手動金鑰解密失敗或未提供，嘗試使用預設金鑰
        if decrypted_data is None and os.path.exists(default_key_path):
            decrypted_data = attempt_decryption(default_key_path)

        if decrypted_data is None:
            # 解密失敗的訊息
            message = f"❌ 解密失敗：{os.path.basename(file_path)}\n預設金鑰錯誤或檔案損壞。"
            if provided_key_path:
                if not os.path.exists(provided_key_path):
                    message = f"❌ 解密失敗：{os.path.basename(file_path)}\n指定的金鑰檔案不存在。"
                else:
                    message = f"❌ 解密失敗：{os.path.basename(file_path)}\n指定的金鑰錯誤或檔案損壞。"

            self.messageSignal.emit("錯誤", message)
            self._log_action('decrypt', file_path, 'FAILED', message.replace('\n', ' '))
            return False

        try:
            with open(original_path, 'wb') as f:
                f.write(decrypted_data) # 將解密資料寫回原始檔案路徑
            
            os.remove(file_path) # 刪除加密檔案

            self._log_action('decrypt', original_path)
            self.messageSignal.emit("成功", f"✅ 解密完成，還原檔案：{os.path.basename(original_path)}")
            return True
        except Exception as e:
            # 捕獲解密後寫入檔案的錯誤
            self._log_action('decrypt', file_path, 'FAILED', f"Failed to write decrypted data: {str(e)}")
            self.messageSignal.emit("錯誤", f"❌ 解密檔案寫入失敗：{os.path.basename(file_path)}\n錯誤：{str(e)}")
            return False

    def process_files(self, file_paths: list, mode: str, manual_key_path: str = None):
        # 處理檔案列表的主函數
        success_count = 0
        fail_count = 0

        # 在開始處理一批檔案前，清空錯誤日誌
        if os.path.exists(os.path.join(self.base_dir, ERROR_LOG_FILE)):
            os.remove(os.path.join(self.base_dir, ERROR_LOG_FILE))

        if not file_paths:
            self.processingFinished.emit(0, 0, ERROR_LOG_FILE)
            return

        for i, file_path in enumerate(file_paths):
            result = False
            try:
                if mode == 'encrypt':
                    result = self._encrypt_file_internal(file_path)
                elif mode == 'decrypt':
                    result = self._decrypt_file_internal(file_path, manual_key_path)
                else:
                    self.messageSignal.emit("錯誤", "無效的操作模式。")
                    self._log_action('process', file_path, 'FAILED', 'Invalid mode')
            except Exception as e:
                # 捕獲處理單個檔案時的意外錯誤
                current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with open(os.path.join(self.base_dir, ERROR_LOG_FILE), 'a', encoding='utf-8') as log:
                    log.write(f"[{current_time}]\n檔案: {file_path}\n處理錯誤: {str(e)}\n\n")
                result = False

            if result:
                success_count += 1
            else:
                fail_count += 1

            # 更新進度條
            progress = int((i + 1) / len(file_paths) * 100)
            self.progressUpdated.emit(progress)

        # 處理完成後發送訊號
        self.processingFinished.emit(success_count, fail_count, ERROR_LOG_FILE)


# 主視窗類別
class MainWindow(QtWidgets.QWidget, Ui_Form):
    def __init__(self):
        super().__init__()
        self.setupUi(self)

        # 處理模式，預設為加密
        self.current_processing_mode = 'encrypt'
        # 手動解密金鑰路徑，預設為None
        self.manual_decryption_key_path = None

        # 連接UI元件的訊號與槽
        self.pushButton_select.clicked.connect(self.open_files)
        self.pushButton_remove.clicked.connect(self.remove_selected_files)
        self.pushButton_execute.clicked.connect(self.start_processing)
        self.pushButton_select_key.clicked.connect(self.select_manual_key)

        self.radio_encrypt.toggled.connect(self.on_mode_toggled)
        self.radio_decrypt.toggled.connect(self.on_mode_toggled)

        # 設定ListWidget的拖放功能和多選模式
        self.listWidget.setAcceptDrops(True)
        self.listWidget.setDragDropMode(QtWidgets.QAbstractItemView.DragDropMode.DropOnly)
        self.listWidget.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
        self.listWidget.installEventFilter(self) # 安裝事件過濾器以處理拖放事件

        # 初始化檔案處理器並連接其訊號
        self.file_processor = FileProcessor()
        self.file_processor.progressUpdated.connect(self.update_progress_bar)
        self.file_processor.processingFinished.connect(self.show_summary)
        self.file_processor.messageSignal.connect(self.display_message) # 連接訊息顯示訊號

        # 初始化線程池，用於異步處理檔案，避免UI凍結
        self.thread_pool = ThreadPoolExecutor(max_workers=1) # 設置為1確保檔案順序處理

        # 設定右鍵選單
        self.context_menu = QMenu(self)
        self.context_menu.addAction("開啟資料夾", self.open_folder)
        self.context_menu.addAction("刪除選擇", self.remove_selected_files)
        self.context_menu.addAction("清空全部", self.clear_all_files)
        self.context_menu.setStyleSheet(
            "QMenu { background-color: #3b4252; border: 1px solid #4c566a; color: #eceff4; }"
            "QMenu::item { padding: 5px 20px; }"
            "QMenu::item:selected { background-color: #5e81ac; }"
        )

        # 初始化模式切換，以設定金鑰選擇元件的初始可見性
        self.on_mode_toggled()

    def on_mode_toggled(self):
        """處理加密/解密模式切換的邏輯。"""
        if self.radio_encrypt.isChecked():
            self.current_processing_mode = 'encrypt'
            self.pushButton_select_key.setVisible(False)
            self.label_key_path.setVisible(False)
            self.manual_decryption_key_path = None # 切換到加密模式時清空金鑰路徑
            self.label_key_path.setText("未選擇金鑰檔案") # 重設標籤文字
        elif self.radio_decrypt.isChecked():
            self.current_processing_mode = 'decrypt'
            self.pushButton_select_key.setVisible(True)
            self.label_key_path.setVisible(True)

    def select_manual_key(self):
        """打開檔案對話框，讓使用者選擇解密金鑰檔案。"""
        key_path, _ = QFileDialog.getOpenFileName(self, "選擇金鑰檔案", "", "金鑰檔案 (*.key);;所有文件 (*)")
        if key_path:
            self.manual_decryption_key_path = key_path
            self.label_key_path.setText(os.path.basename(key_path)) # 顯示金鑰檔案名稱
        else:
            self.manual_decryption_key_path = None
            self.label_key_path.setText("未選擇金鑰檔案")

    def display_message(self, title: str, message: str):
        """在QMessageBox中顯示訊息。"""
        QMessageBox.information(self, title, message)

    def keyPressEvent(self, event: QtGui.QKeyEvent):
        # 處理鍵盤事件 (例如: Delete鍵刪除選定項目, Ctrl+A全選)
        if event.key() == QtCore.Qt.Key.Key_Delete:
            self.remove_selected_files()
        elif event.key() == QtCore.Qt.Key.Key_A and event.modifiers() == QtCore.Qt.KeyboardModifier.ControlModifier:
            self.listWidget.selectAll()
        super().keyPressEvent(event)

    def eventFilter(self, source, event):
        # 事件過濾器，處理ListWidget的拖放事件
        if source == self.listWidget:
            if event.type() == QtCore.QEvent.Type.DragEnter:
                if event.mimeData().hasUrls():
                    event.acceptProposedAction()
                    return True
            elif event.type() == QtCore.QEvent.Type.Drop:
                for url in event.mimeData().urls():
                    file_path = url.toLocalFile()
                    if os.path.exists(file_path): # 確保拖放的路徑存在
                        if not self.is_duplicate(file_path):
                            self.listWidget.addItem(file_path)
                return True
        return super().eventFilter(source, event)

    def dragEnterEvent(self, event):
        # 拖放進入事件，檢查MIME資料是否包含URL
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        # 拖放檔案到ListWidget的處理
        for url in event.mimeData().urls():
            file_path = url.toLocalFile()
            if os.path.exists(file_path): # 確保拖放的路徑存在
                if not self.is_duplicate(file_path):
                    self.listWidget.addItem(file_path)

    def open_files(self):
        """打開檔案選擇對話框，讓使用者選擇要處理的檔案。"""
        file_paths, _ = QtWidgets.QFileDialog.getOpenFileNames(self, "選擇文件", "", "所有文件 (*)")
        for file_path in file_paths:
            if os.path.exists(file_path): # 確保選擇的路徑存在
                if not self.is_duplicate(file_path):
                    self.listWidget.addItem(file_path)

    def is_duplicate(self, file_path):
        """檢查檔案路徑是否已存在於列表中，防止重複添加。"""
        for i in range(self.listWidget.count()):
            if self.listWidget.item(i).text() == file_path:
                return True
        return False

    def remove_selected_files(self):
        """刪除ListWidget中選定的檔案項目。"""
        selected_items = self.listWidget.selectedItems()
        for item in selected_items:
            self.listWidget.takeItem(self.listWidget.row(item))

    def clear_all_files(self):
        """清空ListWidget中的所有檔案項目，並重設進度條。"""
        self.listWidget.clear()
        self.progressBar.setValue(0) # 清空時重設進度條

    def contextMenuEvent(self, event: QContextMenuEvent):
        """顯示右鍵選單。"""
        self.context_menu.exec(event.globalPos())

    def update_progress_bar(self, value):
        """更新進度條的顯示值。"""
        self.progressBar.setValue(value)

    def show_summary(self, success_count: int, fail_count: int, log_file: str):
        """顯示處理結果的摘要訊息框。"""
        self.progressBar.setValue(100) # 完成後設置為100%
        if fail_count > 0:
            message = f"完成: {success_count} 個，失敗: {fail_count} 個\n詳細錯誤請查看 {log_file} 檔案。"
            QMessageBox.warning(self, "處理結果", message)
        else:
            message = f"完成: {success_count} 個，失敗: {fail_count} 個"
            QMessageBox.information(self, "處理結果", message)
        
        # 處理完成後，可以選擇清空列表 (如果需要的話)
        # self.listWidget.clear() 

        # 啟用所有按鈕和模式選擇
        self.enable_buttons_after_processing()

    def start_processing(self):
        """開始檔案處理流程。"""
        if self.listWidget.count() == 0:
            QMessageBox.warning(self, "警告", "請選擇至少一個文件進行處理")
            return

        file_paths = [self.listWidget.item(i).text() for i in range(self.listWidget.count())]
        self.progressBar.setValue(0) # 開始前重設進度條
        
        # 在處理過程中禁用所有相關按鈕和模式選擇，防止重複操作
        self.pushButton_select.setEnabled(False)
        self.pushButton_remove.setEnabled(False)
        self.pushButton_execute.setEnabled(False)
        self.pushButton_select_key.setEnabled(False) # 處理過程中禁用金鑰選擇
        self.radio_encrypt.setEnabled(False)
        self.radio_decrypt.setEnabled(False)

        # 將檔案處理任務提交到線程池異步執行
        future = self.thread_pool.submit(
            self.file_processor.process_files,
            file_paths,
            self.current_processing_mode,
            self.manual_decryption_key_path
        )
        
        # 處理完成後，通過回調函數重新啟用按鈕
        future.add_done_callback(lambda _: self.enable_buttons_after_processing())

    def enable_buttons_after_processing(self):
        """在檔案處理完成後啟用所有相關按鈕和模式選擇。"""
        self.pushButton_select.setEnabled(True)
        self.pushButton_remove.setEnabled(True)
        self.pushButton_execute.setEnabled(True)
        self.radio_encrypt.setEnabled(True)
        self.radio_decrypt.setEnabled(True)
        # 根據當前選擇的模式重新評估金鑰選擇按鈕的可見性
        self.on_mode_toggled() 

    def open_folder(self):
        """打開選定檔案所在資料夾。"""
        selected_items = self.listWidget.selectedItems()
        if selected_items:
            for item in selected_items:
                file_path = item.text()
                folder_path = os.path.dirname(file_path)
                folder_path = Path(folder_path) # 使用pathlib處理路徑

                if not folder_path.exists() or not folder_path.is_dir():
                    QMessageBox.warning(self, "警告", f"資料夾不存在: {folder_path}")
                    continue

                try:
                    # 跨平台打開資料夾
                    if sys.platform == "win32":
                        os.startfile(str(folder_path))
                    elif sys.platform == "darwin": # macOS
                        import subprocess
                        subprocess.Popen(["open", str(folder_path)])
                    else: # Linux
                        import subprocess
                        subprocess.Popen(["xdg-open", str(folder_path)])
                except Exception as e:
                    QMessageBox.critical(self, "錯誤", f"開啟資料夾失敗:\n{e}")

# 程式進入點
if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    mainWindow = MainWindow()
    mainWindow.show()
    sys.exit(app.exec())
