import qrcode
from pyzbar.pyzbar import decode
from PIL import Image
from PIL import ImageTk
import tkinter as tk
from tkinter import messagebox, simpledialog
from tkinter import filedialog
import sys
import os
import json
import base64
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Random import get_random_bytes
import secrets


KEYS_DIR = "keys"
ENCRYPTED_KEYS_DIR = os.path.join(KEYS_DIR, "encrypted")
DECRYPTED_KEYS_DIR = os.path.join(KEYS_DIR, "decrypted")


class EncryptionUtils:
    """自定义加密工具类"""
    
    @staticmethod
    def custom_encrypt(text, password):
        """内层自定义加密算法"""
        try:
            text_bytes = text.encode('utf-8')
            
            # 计算Key = (密码各位数字之和 × 密码) mod 256
            digit_sum = sum(int(c) for c in password if c.isdigit())
            key = (digit_sum * len(password)) % 256
            
            encrypted = []
            for byte in text_bytes:
                c = (byte + key) % 256
                C = c ^ key
                encrypted.append(C)
            
            # 结果倒序，转16进制
            encrypted.reverse()
            hex_result = ''.join(f'{b:02x}' for b in encrypted)
            
            return hex_result
        except Exception as e:
            raise Exception(f"内层加密失败: {e}")
    
    @staticmethod
    def custom_decrypt(hex_text, password):
        """内层自定义解密算法"""
        try:
            # 16进制转字节
            encrypted = bytes.fromhex(hex_text)
            
            # 计算Key = (密码各位数字之和 × 密码) mod 256
            digit_sum = sum(int(c) for c in password if c.isdigit())
            key = (digit_sum * len(password)) % 256
            
            # 倒序
            encrypted_list = list(encrypted)
            encrypted_list.reverse()
            
            decrypted = []
            for C in encrypted_list:
                c = C ^ key
                byte = (c - key) % 256
                decrypted.append(byte)
            
            return bytes(decrypted).decode('utf-8')
        except Exception as e:
            raise Exception(f"内层解密失败: {e}")
    
    @staticmethod
    def rsa_encrypt(text, public_key_pem):
        """外层RSA公钥加密"""
        try:
            public_key = RSA.import_key(public_key_pem)
            cipher = PKCS1_v1_5.new(public_key)
            
            # 分块加密
            max_chunk_size = 117  # RSA 1024位密钥的最大块大小
            encrypted_chunks = []
            
            for i in range(0, len(text), max_chunk_size):
                chunk = text[i:i + max_chunk_size].encode('utf-8')
                encrypted_chunk = cipher.encrypt(chunk)
                encrypted_chunks.append(encrypted_chunk)
            
            # 将所有加密块合并并base64编码
            combined = b''.join(encrypted_chunks)
            return base64.b64encode(combined).decode('utf-8')
        except Exception as e:
            raise Exception(f"RSA加密失败: {e}")
    
    @staticmethod
    def rsa_decrypt(base64_text, private_key_pem, password):
        """外层RSA私钥解密"""
        try:
            private_key = RSA.import_key(private_key_pem)
            cipher = PKCS1_v1_5.new(private_key)
            
            # base64解码
            combined = base64.b64decode(base64_text)
            
            # 分块解密
            key_size = private_key.size_in_bytes()
            max_chunk_size = key_size
            
            decrypted_chunks = []
            for i in range(0, len(combined), max_chunk_size):
                chunk = combined[i:i + max_chunk_size]
                decrypted_chunk = cipher.decrypt(chunk, None)
                if decrypted_chunk is None:
                    raise Exception("解密失败")
                decrypted_chunks.append(decrypted_chunk)
            
            return b''.join(decrypted_chunks).decode('utf-8')
        except Exception as e:
            raise Exception(f"RSA解密失败: {e}")


class KeyManager:
    """密钥管理类"""
    
    @staticmethod
    def ensure_dirs():
        """确保目录存在"""
        for dir_path in [KEYS_DIR, ENCRYPTED_KEYS_DIR, DECRYPTED_KEYS_DIR]:
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
    
    @staticmethod
    def generate_key_pair(password1, password2):
        """生成密钥对"""
        try:
            KeyManager.ensure_dirs()
            
            # 生成RSA密钥对
            key = RSA.generate(1024)
            private_key = key.export_key()
            public_key = key.publickey().export_key()
            
            # 使用password2加密私钥
            encrypted_private_key = EncryptionUtils.custom_encrypt(
                private_key.decode('utf-8'), password2
            )
            
            # 创建密钥数据
            key_data = {
                'public_key': public_key.decode('utf-8'),
                'encrypted_private_key': encrypted_private_key
            }
            
            # 生成二维码
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(json.dumps(key_data))
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            
            return img
        except Exception as e:
            raise Exception(f"生成密钥失败: {e}")
    
    @staticmethod
    def load_key(password, img_path):
        """加载密钥"""
        try:
            KeyManager.ensure_dirs()
            
            # 解码二维码
            img = Image.open(img_path)
            result = decode(img)
            
            if not result:
                raise Exception("未找到有效的二维码数据")
            
            key_data_str = result[0][0].decode('utf-8', errors='ignore')
            key_data = json.loads(key_data_str)
            
            # 解密私钥
            encrypted_private_key = key_data['encrypted_private_key']
            private_key_str = EncryptionUtils.custom_decrypt(encrypted_private_key, password)
            
            # 保存加密的密钥文件
            encrypted_filename = f"key_{secrets.token_hex(4)}.txt"
            encrypted_path = os.path.join(ENCRYPTED_KEYS_DIR, encrypted_filename)
            
            with open(encrypted_path, 'w', encoding='utf-8') as f:
                f.write(key_data['encrypted_private_key'])
            
            # 保存解密的密钥文件
            decrypted_filename = f"key_{secrets.token_hex(4)}.txt"
            decrypted_path = os.path.join(DECRYPTED_KEYS_DIR, decrypted_filename)
            
            with open(decrypted_path, 'w', encoding='utf-8') as f:
                f.write(private_key_str)
            
            return decrypted_path
        except Exception as e:
            raise Exception(f"加载密钥失败: {e}")
    
    @staticmethod
    def get_available_keys():
        """获取可用的密钥文件列表"""
        try:
            KeyManager.ensure_dirs()
            
            keys = []
            for filename in os.listdir(DECRYPTED_KEYS_DIR):
                if filename.endswith('.txt'):
                    keys.append(filename)
            
            return keys
        except Exception as e:
            raise Exception(f"获取密钥列表失败: {e}")


class QRCodeApp:
    def __init__(self, root):
        self.root = root
        
        self.root.geometry("300x200")
        self.root.title("加密二维码")
        self.root.resizable(False, False)
        
        self.labels = []
        self.current_qr_img = None
        self.loaded_private_key = None
        self.loaded_public_key = None
        
        self.init_ui()
    
    def init_ui(self):
        # 菜单栏
        menu_bar = tk.Menu(self.root)
        self.root.config(menu=menu_bar)
        
        encrypt_menu = tk.Menu(menu_bar, tearoff=0)
        encrypt_menu.add_command(label="加密二维码", command=self.encrypt_qrcode)
        encrypt_menu.add_command(label="解密二维码", command=self.decrypt_qrcode)
        encrypt_menu.add_command(label="生成密钥", command=self.generate_key)
        encrypt_menu.add_command(label="加载密钥", command=self.load_key)
        menu_bar.add_cascade(label="加密二维码", menu=encrypt_menu)
        
        menu_bar.add_command(label="关于", command=self.show_about)
        
        # 按钮
        self.make_button = tk.Button(self.root, text="制作二维码", command=self.generate_qrcode)
        self.make_button.place(x=30, y=30)
        
        self.unmake_button = tk.Button(self.root, text="二维码解码", command=self.decode_qrcode)
        self.unmake_button.place(x=30, y=80)
        
        self.save_button = tk.Button(self.root, text="保存二维码", command=self.save_qrcode)
        self.save_button.place(x=30, y=130)
        
        self.show_github_qrcode()
    
    def show_github_qrcode(self):
        github_url = "https://github.com/liang-rising-star/Py-zebra-QR-Code-Generator"
        self.generate_qrcode_from_text(github_url, show_only=True)
    
    def show_photo(self, img):
        size = 150
        try:
            img_open = img.copy()
            img_open = img_open.resize((size, size))
            img_png = ImageTk.PhotoImage(img_open)
            
            if self.labels:
                old_label, old_img_png = self.labels[0]
                old_label.destroy()
                self.labels.clear()
            
            label = tk.Label(self.root, image=img_png)
            label.place(x=120, y=20)
            label.img_png = img_png
            self.labels.append((label, img_png))
            
            self.current_qr_img = img
        except Exception as e:
            print(f"显示图片时出错: {e}")
    
    def generate_qrcode_from_text(self, text, show_only=True):
        try:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(text)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            
            if show_only:
                self.show_photo(img)
            else:
                return img
        except Exception as e:
            messagebox.showerror("错误", f"生成二维码时出错: {e}")
            return None
    
    def generate_qrcode(self):
        content = filedialog.askopenfilename(
            title="选择文件",
            filetypes=[
                ("文本文件 (*.txt)", "*.txt"),
                ("所有文件", "*.*")
            ]
        )
        
        if not content:
            return
        
        try:
            with open(content, 'r', encoding='utf-8') as f:
                data = f.read()
            
            self.generate_qrcode_from_text(data, show_only=True)
            messagebox.showinfo("成功", "二维码已生成并显示")
        except UnicodeDecodeError:
            try:
                with open(content, 'r', encoding='gbk') as f:
                    data = f.read()
                self.generate_qrcode_from_text(data, show_only=True)
                messagebox.showinfo("成功", "二维码已生成并显示")
            except Exception as e:
                messagebox.showerror("错误", f"读取文件时出错: {e}")
        except Exception as e:
            messagebox.showerror("错误", f"生成二维码时出错: {e}")
    
    def save_qrcode(self):
        if self.current_qr_img is None:
            messagebox.showwarning("警告", "没有可保存的二维码")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="保存二维码",
            defaultextension=".png",
            filetypes=[("PNG 图片", "*.png"), ("所有文件", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            self.current_qr_img.save(file_path)
            messagebox.showinfo("成功", f"二维码已保存到: {file_path}")
        except Exception as e:
            messagebox.showerror("错误", f"保存二维码时出错: {e}")
    
    def decode_qrcode(self):
        img_path = filedialog.askopenfilename(
            title="选择文件",
            filetypes=[
                ("图片文件 (*.png;*.jpg;*.jpeg;*.bmp)", "*.png;*.jpg;*.jpeg;*.bmp"),
                ("所有文件", "*.*")
            ]
        )
        
        if not img_path:
            return
        
        try:
            img = Image.open(img_path)
            result = decode(img)
            
            if result:
                decoded_data = result[0][0].decode('utf-8', errors='ignore')
                messagebox.showinfo("成功", decoded_data)
            else:
                messagebox.showwarning("警告", "未找到有效的二维码数据")
        except FileNotFoundError:
            messagebox.showerror("错误", "文件不存在")
        except Exception as e:
            messagebox.showerror("错误", f"解码失败: {e}")
    
    def generate_key(self):
        """生成密钥功能"""
        try:
            # 输入两个密码
            password1 = simpledialog.askstring("输入密码", "请输入生成密钥的密码:", show='*')
            if not password1:
                return
            
            password2 = simpledialog.askstring("输入密码", "请输入解开密钥的密码:", show='*')
            if not password2:
                return
            
            # 生成密钥对
            img = KeyManager.generate_key_pair(password1, password2)
            
            # 保存二维码
            file_path = filedialog.asksaveasfilename(
                title="保存密钥二维码",
                defaultextension=".png",
                filetypes=[("PNG 图片", "*.png"), ("所有文件", "*.*")]
            )
            
            if not file_path:
                return
            
            img.save(file_path)
            messagebox.showinfo("成功", f"密钥已生成并保存到: {file_path}")
        except Exception as e:
            messagebox.showerror("错误", f"生成密钥失败: {e}")
    
    def load_key(self):
        """加载密钥功能"""
        try:
            # 获取可用密钥文件
            keys = KeyManager.get_available_keys()
            
            if not keys:
                # 如果没有密钥文件，需要先解密
                password = simpledialog.askstring("输入密码", "请输入解开密钥的密码:", show='*')
                if not password:
                    return
                
                img_path = filedialog.askopenfilename(
                    title="选择密钥二维码",
                    filetypes=[("图片文件 (*.png)", "*.png"), ("所有文件", "*.*")]
                )
                
                if not img_path:
                    return
                
                decrypted_path = KeyManager.load_key(password, img_path)
                messagebox.showinfo("成功", f"密钥加载成功: {decrypted_path}")
            else:
                # 显示可用密钥列表
                key_window = tk.Toplevel(self.root)
                key_window.title("选择密钥")
                key_window.geometry("300x200")
                key_window.transient(self.root)
                key_window.grab_set()
                
                tk.Label(key_window, text="选择密钥文件:").pack(pady=10)
                
                key_var = tk.StringVar(key_window)
                key_var.set(keys[0] if keys else "")
                
                key_menu = tk.OptionMenu(key_window, key_var, *keys)
                key_menu.pack(pady=10)
                
                password_entry = tk.Entry(key_window, show='*', width=30)
                password_entry.pack(pady=10)
                password_entry.insert(0, "请输入密码")
                
                def confirm():
                    selected_key = key_var.get()
                    password = password_entry.get()
                    
                    if password == "请输入密码" or not password:
                        messagebox.showwarning("警告", "请输入密码")
                        return
                    
                    try:
                        encrypted_path = os.path.join(ENCRYPTED_KEYS_DIR, selected_key)
                        with open(encrypted_path, 'r', encoding='utf-8') as f:
                            encrypted_private_key = f.read()
                        
                        # 解密私钥
                        private_key_str = EncryptionUtils.custom_decrypt(encrypted_private_key, password)
                        
                        # 保存解密的密钥
                        decrypted_path = os.path.join(DECRYPTED_KEYS_DIR, selected_key)
                        with open(decrypted_path, 'w', encoding='utf-8') as f:
                            f.write(private_key_str)
                        
                        messagebox.showinfo("成功", "密钥加载成功")
                        key_window.destroy()
                    except Exception as e:
                        messagebox.showerror("错误", f"加载密钥失败: {e}")
                
                tk.Button(key_window, text="确认", command=confirm).pack(pady=10)
        except Exception as e:
            messagebox.showerror("错误", f"加载密钥失败: {e}")
    
    def encrypt_qrcode(self):
        """加密二维码功能"""
        try:
            # 检查是否有公钥
            if not self.loaded_public_key:
                keys = KeyManager.get_available_keys()
                if not keys:
                    messagebox.showwarning("警告", "请先加载公钥")
                    return
                
                # 选择公钥
                key_window = tk.Toplevel(self.root)
                key_window.title("选择公钥")
                key_window.geometry("300x200")
                key_window.transient(self.root)
                key_window.grab_set()
                
                tk.Label(key_window, text="选择公钥文件:").pack(pady=10)
                
                key_var = tk.StringVar(key_window)
                key_var.set(keys[0] if keys else "")
                
                key_menu = tk.OptionMenu(key_window, key_var, *keys)
                key_menu.pack(pady=10)
                
                def confirm():
                    selected_key = key_var.get()
                    try:
                        decrypted_path = os.path.join(DECRYPTED_KEYS_DIR, selected_key)
                        with open(decrypted_path, 'r', encoding='utf-8') as f:
                            self.loaded_public_key = f.read()
                        messagebox.showinfo("成功", "公钥加载成功")
                        key_window.destroy()
                    except Exception as e:
                        messagebox.showerror("错误", f"加载公钥失败: {e}")
                
                tk.Button(key_window, text="确认", command=confirm).pack(pady=10)
                key_window.wait_window()
                
                if not self.loaded_public_key:
                    return
            
            # 输入要加密的文本
            text = simpledialog.askstring("输入文本", "请输入需要加密的文本内容:")
            if not text:
                return
            
            # 双层加密
            try:
                # 内层加密
                inner_encrypted = EncryptionUtils.custom_encrypt(text, "default_password")
                
                # 外层RSA加密
                outer_encrypted = EncryptionUtils.rsa_encrypt(inner_encrypted, self.loaded_public_key)
                
                # 生成二维码
                img = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_L,
                    box_size=10,
                    border=4,
                )
                img.add_data(outer_encrypted)
                img.make(fit=True)
                qr_img = img.make_image(fill_color="black", back_color="white")
                
                # 保存二维码
                file_path = filedialog.asksaveasfilename(
                    title="保存加密二维码",
                    defaultextension=".png",
                    filetypes=[("PNG 图片", "*.png"), ("所有文件", "*.*")]
                )
                
                if file_path:
                    qr_img.save(file_path)
                    messagebox.showinfo("成功", f"加密二维码已生成并保存到: {file_path}")
            except Exception as e:
                messagebox.showerror("错误", f"加密失败: {e}")
        except Exception as e:
            messagebox.showerror("错误", f"加密二维码失败: {e}")
    
    def decrypt_qrcode(self):
        """解密二维码功能"""
        try:
            # 加载密钥
            keys = KeyManager.get_available_keys()
            if not keys:
                messagebox.showwarning("警告", "请先加载密钥")
                return
            
            # 选择密钥
            key_window = tk.Toplevel(self.root)
            key_window.title("选择密钥")
            key_window.geometry("300x200")
            key_window.transient(self.root)
            key_window.grab_set()
            
            tk.Label(key_window, text="选择密钥文件:").pack(pady=10)
            
            key_var = tk.StringVar(key_window)
            key_var.set(keys[0] if keys else "")
            
            key_menu = tk.OptionMenu(key_window, key_var, *keys)
            key_menu.pack(pady=10)
            
            password_entry = tk.Entry(key_window, show='*', width=30)
            password_entry.pack(pady=10)
            
            def confirm():
                selected_key = key_var.get()
                password = password_entry.get()
                
                if not password:
                    messagebox.showwarning("警告", "请输入密码")
                    return
                
                try:
                    decrypted_path = os.path.join(DECRYPTED_KEYS_DIR, selected_key)
                    with open(decrypted_path, 'r', encoding='utf-8') as f:
                        self.loaded_private_key = f.read()
                    messagebox.showinfo("成功", "密钥加载成功")
                    key_window.destroy()
                except Exception as e:
                    messagebox.showerror("错误", f"加载密钥失败: {e}")
            
            tk.Button(key_window, text="确认", command=confirm).pack(pady=10)
            key_window.wait_window()
            
            if not self.loaded_private_key:
                return
            
            # 选择要解密的二维码
            img_path = filedialog.askopenfilename(
                title="选择加密二维码",
                filetypes=[("图片文件 (*.png)", "*.png"), ("所有文件", "*.*")]
            )
            
            if not img_path:
                return
            
            # 解密二维码
            try:
                img = Image.open(img_path)
                result = decode(img)
                
                if not result:
                    messagebox.showerror("错误", "未找到有效的二维码数据")
                    return
                
                encrypted_data = result[0][0].decode('utf-8', errors='ignore')
                
                # 外层RSA解密
                outer_decrypted = EncryptionUtils.rsa_decrypt(encrypted_data, self.loaded_private_key, "temp")
                
                # 内层解密
                decrypted_text = EncryptionUtils.custom_decrypt(outer_decrypted, "default_password")
                
                # 保存到code.txt
                output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "code.txt")
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(decrypted_text)
                
                messagebox.showinfo("成功", f"解密成功!\n内容: {decrypted_text}\n已保存到: {output_path}")
            except Exception as e:
                messagebox.showerror("错误", f"解密失败: {e}")
        except Exception as e:
            messagebox.showerror("错误", f"解密二维码失败: {e}")
    
    def show_about(self):
        messagebox.showinfo(
            "关于",
            "Py-Zebra QR Code Generator\n\n"
            "Copyright© 2026 liang-rising-star\n"
            "Powered by liang-rising-star\n\n"
            "GitHub 仓库：\n"
            "https://github.com/liang-rising-star/Py-Zebra"
        )


def zebra(content, output_path=None):
    """生成二维码
    
    Args:
        content: 要编码的内容（字符串或文件路径）
        output_path: 输出路径（可选），如果为None则返回PIL Image对象
    
    Returns:
        PIL Image对象或保存成功消息
    """
    try:
        if isinstance(content, str) and content.endswith('.txt'):
            with open(content, 'r', encoding='utf-8') as f:
                data = f.read()
        else:
            data = content
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        if output_path:
            img.save(output_path)
            return f"二维码已保存到: {output_path}"
        else:
            return img
    except Exception as e:
        return f"生成二维码时出错: {e}"


def unzebra(img_path):
    """解码二维码
    
    Args:
        img_path: 二维码图片路径
    
    Returns:
        解码后的字符串或错误信息
    """
    try:
        img = Image.open(img_path)
        result = decode(img)
        
        if result:
            return result[0][0].decode('utf-8', errors='ignore')
        else:
            return "未找到有效的二维码数据"
    except FileNotFoundError:
        return f"文件不存在: {img_path}"
    except Exception as e:
        return f"解码失败: {e}"


def main():
    root = tk.Tk()
    app = QRCodeApp(root)
    root.mainloop()


if __name__ == '__main__':
    if len(sys.argv) > 1:
        if sys.argv[1] == 'zebra' and len(sys.argv) >= 3:
            input_path = sys.argv[2]
            output_path = sys.argv[3] if len(sys.argv) > 3 else None
            result = zebra(input_path, output_path)
            print(result)
        elif sys.argv[1] == 'unzebra' and len(sys.argv) >= 3:
            img_path = sys.argv[2]
            result = unzebra(img_path)
            print(result)
        else:
            print("用法: python main.py zebra <输入文件> [输出路径]")
            print("     python main.py unzebra <二维码图片路径>")
    else:
        main()
