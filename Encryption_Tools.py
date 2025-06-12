import os
import sys
import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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


def encrypt_file(file_path: str):
    if file_path.endswith(SUFFIX):
        print("⚠️ 檔案似乎已加密，跳過加密。")
        return

    key = generate_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)

    with open(file_path, 'rb') as f:
        data = f.read()

    encrypted_data = aesgcm.encrypt(nonce, data, None)

    encrypted_path = file_path + SUFFIX
    with open(encrypted_path, 'wb') as f:
        f.write(nonce + encrypted_data)

    os.remove(file_path)

    key_filename = os.path.basename(file_path) + '.key'
    key_path = os.path.join(get_key_dir(), key_filename)
    with open(key_path, 'wb') as f:
        f.write(key)

    log_action('encrypt', encrypted_path)
    print(f"✅ 檔案加密完成：{encrypted_path}")
    print(f"🔑 金鑰已儲存於：{key_path}")


def decrypt_file(file_path: str):
    if not file_path.endswith(SUFFIX):
        print("❌ 此檔案不是加密檔案")
        return

    original_path = file_path[:-len(SUFFIX)]
    default_key_filename = os.path.basename(original_path) + '.key'
    default_key_path = os.path.join(get_key_dir(), default_key_filename)

    def try_decrypt(key_path_to_use):
        try:
            with open(key_path_to_use, 'rb') as f:
                key = f.read()

            with open(file_path, 'rb') as f:
                content = f.read()
                nonce = content[:12]
                encrypted_data = content[12:]

            aesgcm = AESGCM(key)
            decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
            return decrypted_data
        except Exception:
            return None

    decrypted_data = try_decrypt(default_key_path)

    if decrypted_data is None:
        print("❌ 解密失敗，預設金鑰錯誤或檔案損壞。")
        choice = input("是否要手動指定金鑰檔案？[y/N]：").strip().lower()
        if choice == 'y':
            key_path = input("請輸入金鑰（.key）檔案的完整路徑：").strip()
            if not os.path.exists(key_path):
                print("❌ 找不到指定的金鑰檔案。")
                return
            decrypted_data = try_decrypt(key_path)
            if decrypted_data is None:
                print("❌ 解密仍失敗，金鑰錯誤或檔案已損壞。")
                return
        else:
            return

    with open(original_path, 'wb') as f:
        f.write(decrypted_data)

    os.remove(file_path)
    log_action('decrypt', original_path)
    print(f"✅ 解密完成，還原檔案：{original_path}")


# ====== CLI 執行區 ======
if __name__ == "__main__":
    print("🔐 加密 / 解密工具（副檔名方式 + 金鑰管理 + 紀錄）")
    choice = input("請選擇 [e] 加密 / [d] 解密：").strip().lower()

    if choice == 'e':
        path = input("請輸入欲加密的檔案路徑：").strip()
        encrypt_file(path)
    elif choice == 'd':
        path = input("請輸入欲解密的檔案路徑：").strip()
        decrypt_file(path)
    else:
        print("❌ 無效選項")
