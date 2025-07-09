import socket
import threading
import sys
import time
import os
import base64
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog, filedialog
from PIL import Image, ImageTk
import io
import queue
import datetime
import webbrowser
import tempfile
import sounddevice as sd
import soundfile as sf

# --- RC4 加密解密 ---
def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    out = bytearray()
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out)
RC4_KEY = b'supersecretkey'

# 配置
SERVER_HOST = '192.168.1.102'  # 服务器IP
SERVER_PORT = 62599  # 服务器端口

CUSTOM_ALPHABET = "idhR+nWSPOU0CGIrNmAqVZlYuo2sDt7yg6MBXF1aw4Kv9LHJkjb5p8/zxcefQ3ET"
STANDARD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

ENCODE_TRANS = str.maketrans(STANDARD_ALPHABET, CUSTOM_ALPHABET)
DECODE_TRANS = str.maketrans(CUSTOM_ALPHABET, STANDARD_ALPHABET)

def custom_b64encode(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    standard = base64.b64encode(data).decode('utf-8')
    return standard.translate(ENCODE_TRANS)

def custom_b64decode(data, binary=False):
    standard = data.translate(DECODE_TRANS)
    raw = base64.b64decode(standard)
    if binary:
        return raw
    else:
        return raw.decode('utf-8')

def enc(data):
    return custom_b64encode(data)

def dec(data, binary=False):
    return custom_b64decode(data, binary=binary)

class ChatClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("安全聊天客户端")
        self.root.geometry("900x600")
        self.root.configure(bg="#f0f0f0")
        self.root.minsize(800, 500)

        self.client_socket = None
        self.username = None
        self.current_session = None
        self.running = True
        self.server_host = SERVER_HOST
        self.server_port = SERVER_PORT
        self.last_list_update = time.time()
        self.image_references = []
        self.download_dir = os.path.join(os.getcwd(), "downloads")
        os.makedirs(self.download_dir, exist_ok=True)

        self.create_login_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_login_ui(self):
        self.login_frame = tk.Frame(self.root, bg="#f0f0f0", padx=20, pady=20)
        self.login_frame.pack(expand=True, fill=tk.BOTH)

        tk.Label(self.login_frame, text="安全聊天客户端",
                 font=("Arial", 24, "bold"), bg="#f0f0f0", fg="#333").pack(pady=20)

        server_frame = tk.Frame(self.login_frame, bg="#f0f0f0")
        server_frame.pack(fill=tk.X, pady=5)
        tk.Label(server_frame, text="服务器IP:", bg="#f0f0f0", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        self.server_ip_entry = tk.Entry(server_frame, width=20, font=("Arial", 10))
        self.server_ip_entry.pack(side=tk.LEFT, padx=5)
        self.server_ip_entry.insert(0, self.server_host)
        tk.Label(server_frame, text="端口:", bg="#f0f0f0", font=("Arial", 10)).pack(side=tk.LEFT, padx=(20, 5))
        self.server_port_entry = tk.Entry(server_frame, width=8, font=("Arial", 10))
        self.server_port_entry.pack(side=tk.LEFT, padx=5)
        self.server_port_entry.insert(0, str(self.server_port))

        user_frame = tk.Frame(self.login_frame, bg="#f0f0f0")
        user_frame.pack(fill=tk.X, pady=10)
        tk.Label(user_frame, text="用户名:", bg="#f0f0f0", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        self.username_entry = tk.Entry(user_frame, width=25, font=("Arial", 10))
        self.username_entry.pack(side=tk.LEFT, padx=5)

        login_btn = tk.Button(self.login_frame, text="登录", command=self.login,
                              bg="#4CAF50", fg="white", font=("Arial", 12), width=15)
        login_btn.pack(pady=20)

        info_label = tk.Label(self.login_frame,
            text="使用说明:\n1. 输入用户名和服务器信息\n2. 登录后可以创建或加入会话\n3. 在消息框中输入消息并发送\n4. 使用表情按钮添加表情符号\n5. 使用文件按钮发送文件\n6. 支持语音消息，点击🎤按钮录音发送",
            bg="#f0f0f0", fg="#666", justify=tk.LEFT, font=("Arial", 9))
        info_label.pack(pady=10)

        self.username_entry.focus_set()

    def create_chat_ui(self):
        self.login_frame.destroy()
        main_frame = tk.Frame(self.root, bg="#f0f0f0")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        left_panel = tk.Frame(main_frame, bg="white", width=200, relief=tk.RAISED, borderwidth=1)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_panel.pack_propagate(False)

        session_frame = tk.LabelFrame(left_panel, text="会话管理", bg="white", padx=5, pady=5)
        session_frame.pack(fill=tk.X, padx=5, pady=5)
        tk.Button(session_frame, text="创建会话", command=self.create_session,
                  bg="#2196F3", fg="white", width=12).pack(side=tk.LEFT, padx=2)
        tk.Button(session_frame, text="加入会话", command=self.join_session,
                  bg="#2196F3", fg="white", width=12).pack(side=tk.LEFT, padx=2)
        tk.Button(session_frame, text="离开会话", command=self.leave_session,
                  bg="#FF9800", fg="white", width=12).pack(side=tk.LEFT, padx=2)
        tk.Button(session_frame, text="刷新列表", command=self.refresh_lists,
                  bg="#9C27B0", fg="white", width=12).pack(side=tk.LEFT, padx=2)

        self.session_list_frame = tk.LabelFrame(left_panel, text="可用会话 (0)", bg="white", padx=5, pady=5)
        self.session_list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.session_listbox = tk.Listbox(self.session_list_frame, bg="white", borderwidth=0,
                                          highlightthickness=0, selectbackground="#e0e0e0")
        scrollbar = tk.Scrollbar(self.session_list_frame, orient="vertical", command=self.session_listbox.yview)
        self.session_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.session_listbox.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        self.session_listbox.bind("<Double-Button-1>", self.on_session_double_click)

        self.user_list_frame = tk.LabelFrame(left_panel, text="在线用户 (0)", bg="white", padx=5, pady=5)
        self.user_list_frame.pack(fill=tk.BOTH, padx=5, pady=(0, 5))
        self.user_listbox = tk.Listbox(self.user_list_frame, bg="white", borderwidth=0,
                                       highlightthickness=0, selectbackground="#e0e0e0")
        scrollbar2 = tk.Scrollbar(self.user_list_frame, orient="vertical", command=self.user_listbox.yview)
        self.user_listbox.config(yscrollcommand=scrollbar2.set)
        scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)
        self.user_listbox.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        right_panel = tk.Frame(main_frame, bg="white", relief=tk.RAISED, borderwidth=1)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.chat_title = tk.Label(right_panel, text="未加入会话", bg="#e0e0e0", fg="#333",
                                   font=("Segoe UI", 12, "bold"), padx=10, pady=5, anchor=tk.W)
        self.chat_title.pack(fill=tk.X)

        self.chat_area = scrolledtext.ScrolledText(
            right_panel,
            bg="white",
            fg="#333",
            font=("Segoe UI", 11),
            padx=10,
            pady=10,
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.chat_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.chat_area.tag_config("self", foreground="#0066cc", font=("Segoe UI", 11))
        self.chat_area.tag_config("other", foreground="#333", font=("Segoe UI", 11))
        self.chat_area.tag_config("system", foreground="#666", font=("Segoe UI", 10))
        self.chat_area.tag_config("file", foreground="#009688", font=("Segoe UI", 10))
        self.chat_area.tag_config("filelink", foreground="#1e88e5", font=("Segoe UI", 10, "underline"))
        self.chat_area.tag_config("image", foreground="#4CAF50", font=("Segoe UI", 10))

        input_frame = tk.Frame(right_panel, bg="#f0f0f0", padx=5, pady=5)
        input_frame.pack(fill=tk.X, padx=5, pady=(0, 5))

        self.message_entry = tk.Entry(input_frame, font=("Segoe UI", 11))
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.message_entry.bind("<Return>", self.send_message)

        send_btn = tk.Button(input_frame, text="发送", command=self.send_message,
                             bg="#4CAF50", fg="white", width=8, font=("Segoe UI", 10))
        send_btn.pack(side=tk.RIGHT, padx=5)

        emoji_btn = tk.Button(input_frame, text="😊", command=self.insert_emoji,
                              font=("Segoe UI", 12), width=2, bg="#f0f0f0", relief=tk.FLAT)
        emoji_btn.pack(side=tk.RIGHT, padx=5)
        file_btn = tk.Button(input_frame, text="📁", command=self.send_file,
                             font=("Segoe UI", 12), width=2, bg="#f0f0f0", relief=tk.FLAT)
        file_btn.pack(side=tk.RIGHT, padx=5)
        voice_btn = tk.Button(input_frame, text="🎤", command=self.record_voice,
                              font=("Segoe UI", 12), width=2, bg="#f0f0f0", relief=tk.FLAT)
        voice_btn.pack(side=tk.RIGHT, padx=5)

        self.message_entry.focus_set()
        self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        self.receive_thread.start()
        self.refresh_lists()

    def insert_emoji(self):
        emoji_window = tk.Toplevel(self.root)
        emoji_window.title("选择表情")
        emoji_window.geometry("400x300")
        emoji_window.transient(self.root)
        emoji_window.grab_set()
        emoji_categories = {
            "常用表情": ["😊", "😂", "😍", "👍", "👏", "🙌", "🎉", "❤️", "🤔", "😎",
                         "😢", "😡", "👌", "🙏", "💯", "🔥", "✨", "🌟", "💪", "👀"],
            "动物自然": ["🐶", "🐱", "🐭", "🐹", "🐰", "🦊", "🐻", "🐼", "🐨", "🐯",
                         "🦁", "🐮", "🐷", "🐸", "🐵", "🐔", "🐧", "🐦", "🐤", "🦄"],
            "食物饮料": ["🍎", "🍐", "🍊", "🍋", "🍌", "🍉", "🍇", "🍓", "🍈", "🍒",
                         "🍑", "🍍", "🥭", "🥥", "🥝", "🍅", "🍆", "🥑", "🥦", "🌶️"],
            "交通工具": ["🚗", "🚕", "🚙", "🚌", "🚎", "🏎️", "🚓", "🚑", "🚒", "🚐",
                         "🚚", "🚛", "🚜", "🛴", "🚲", "🛵", "🏍️", "🚨", "🚔", "✈️"],
            "符号标志": ["❤️", "🧡", "💛", "💚", "💙", "💜", "🖤", "💔", "❣️", "💕",
                         "💞", "💓", "💗", "💖", "💘", "💝", "💟", "☮️", "✝️", "☪️"]
        }
        tab_control = ttk.Notebook(emoji_window)
        for category, emojis in emoji_categories.items():
            tab = ttk.Frame(tab_control)
            tab_control.add(tab, text=category)
            frame = tk.Frame(tab)
            frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            for i, emoji_char in enumerate(emojis):
                row, col = divmod(i, 8)
                btn = tk.Button(frame, text=emoji_char, font=("Segoe UI", 16),
                                command=lambda e=emoji_char: self.select_emoji(e, emoji_window),
                                relief=tk.FLAT, bg="#f0f0f0", width=2)
                btn.grid(row=row, column=col, padx=5, pady=5)
        tab_control.pack(expand=1, fill="both")

    def select_emoji(self, emoji_char, window):
        self.message_entry.insert(tk.INSERT, emoji_char)
        window.destroy()
        self.message_entry.focus_set()

    def send_file(self):
        filepath = filedialog.askopenfilename(
            title="选择要发送的文件",
            filetypes=[("所有文件", "*.*")]
        )
        if not filepath:
            return
        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)
        MAX_SIZE = 10 * 1024 * 1024
        if filesize > MAX_SIZE:
            messagebox.showerror("文件过大", f"文件大小超过限制 ({filesize // 1024}KB > {MAX_SIZE // 1024}KB)")
            return
        try:
            with open(filepath, "rb") as f:
                file_bytes = f.read()
                file_data = base64.b64encode(file_bytes).decode('utf-8')
            file_type = "IMAGE" if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')) else "FILE"
            command = f"{file_type}:{self.username}|{filename}|{file_data}"
            self.send_command(command)
            self.display_user_message(self.username, f"发送了文件: {filename}", is_self=True)
        except Exception as e:
            messagebox.showerror("文件错误", f"无法发送文件: {str(e)}")

    def display_image(self, sender, filename, image_data):
        try:
            image_bytes = base64.b64decode(image_data)
            image = Image.open(io.BytesIO(image_bytes))
            width, height = image.size
            max_width = 400
            if width > max_width:
                ratio = max_width / width
                new_height = int(height * ratio)
                image = image.resize((max_width, new_height), Image.LANCZOS)
            photo = ImageTk.PhotoImage(image)
            self.image_references.append(photo)
            self.chat_area.config(state=tk.NORMAL)
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            self.chat_area.insert(tk.END, f"{sender} ({timestamp}):\n", "other")
            self.chat_area.insert(tk.END, "发送了图片: ", "image")
            image_label = tk.Label(self.chat_area, image=photo, bg="white", cursor="hand2")
            image_label.bind("<Button-1>", lambda e: self.open_file(filename, image_bytes))
            self.chat_area.window_create(tk.END, window=image_label)
            self.chat_area.insert(tk.END, f" {filename}\n\n")
            self.chat_area.config(state=tk.DISABLED)
            self.chat_area.yview(tk.END)
        except Exception as e:
            self.display_system_message(f"显示图片失败: {str(e)}")

    def open_file(self, filename, file_bytes=None):
        if file_bytes:
            filepath = os.path.join(self.download_dir, filename)
            counter = 1
            base_name, ext = os.path.splitext(filename)
            while os.path.exists(filepath):
                filename = f"{base_name}({counter}){ext}"
                filepath = os.path.join(self.download_dir, filename)
                counter += 1
            with open(filepath, "wb") as f:
                f.write(file_bytes)
        else:
            filepath = os.path.join(self.download_dir, filename)
        try:
            if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                webbrowser.open(filepath)
            else:
                os.startfile(filepath) if sys.platform == "win32" else os.system(f'open "{filepath}"')
        except Exception as e:
            messagebox.showerror("打开文件失败", f"无法打开文件: {str(e)}")

    def receive_file(self, sender, filename, file_data):
        try:
            file_bytes = base64.b64decode(file_data)
            filepath = os.path.join(self.download_dir, filename)
            counter = 1
            base_name, ext = os.path.splitext(filename)
            while os.path.exists(filepath):
                filename = f"{base_name}({counter}){ext}"
                filepath = os.path.join(self.download_dir, filename)
                counter += 1
            with open(filepath, "wb") as f:
                f.write(file_bytes)
            self.chat_area.config(state=tk.NORMAL)
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            self.chat_area.insert(tk.END, f"{sender} ({timestamp}):\n", "other")
            if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                self.chat_area.insert(tk.END, "发送了图片: ", "image")
            else:
                self.chat_area.insert(tk.END, "发送了文件: ", "file")
            def open_file():
                self.open_file(filename)
            link_label = tk.Label(self.chat_area, text=filename,
                                  fg="#1e88e5", cursor="hand2",
                                  font=("Segoe UI", 10, "underline"))
            link_label.bind("<Button-1>", lambda e: open_file())
            self.chat_area.window_create(tk.END, window=link_label)
            self.chat_area.insert(tk.END, f" ({len(file_bytes) // 1024} KB)\n\n")
            self.chat_area.config(state=tk.DISABLED)
            self.chat_area.yview(tk.END)
        except Exception as e:
            self.display_system_message(f"保存文件失败: {str(e)}")

    def record_voice(self):
        duration = simpledialog.askinteger("语音时长", "请输入录音秒数(最多30秒):", parent=self.root, minvalue=1, maxvalue=30)
        if not duration:
            return
        fs = 16000
        messagebox.showinfo("录音", "点击确认后开始录音，请讲话...", parent=self.root)
        try:
            recording = sd.rec(int(duration * fs), samplerate=fs, channels=1, dtype='int16')
            sd.wait()
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmpfile:
                sf.write(tmpfile.name, recording, fs)
                tmpfile.seek(0)
                file_bytes = tmpfile.read()
                enc_bytes = rc4(RC4_KEY, file_bytes)
                file_data = base64.b64encode(enc_bytes).decode('utf-8')
                filename = f"voice_{datetime.datetime.now().strftime('%H%M%S')}.wav"
                command = f"VOICE:{self.username}|{filename}|{file_data}"
                self.send_command(command)
                self.display_user_message(self.username, f"发送了语音消息: {filename}", is_self=True)
        except Exception as e:
            messagebox.showerror("录音失败", str(e))

    def display_voice(self, sender, filename, file_data):
        enc_bytes = base64.b64decode(file_data)
        file_bytes = rc4(RC4_KEY, enc_bytes)
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.insert(tk.END, f"{sender} ({timestamp}):\n", "other")
        self.chat_area.insert(tk.END, "发送了语音消息: ", "file")
        def play_voice():
            try:
                with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmpfile:
                    tmpfile.write(file_bytes)
                    tmpfile.flush()
                    data, fs = sf.read(tmpfile.name, dtype='int16')
                    sd.play(data, fs)
                    sd.wait()
            except Exception as e:
                messagebox.showerror("播放失败", str(e))
        play_btn = tk.Button(self.chat_area, text="▶️ 播放", command=play_voice, fg="#1e88e5")
        self.chat_area.window_create(tk.END, window=play_btn)
        self.chat_area.insert(tk.END, f" {filename}\n\n")
        self.chat_area.config(state=tk.DISABLED)
        self.chat_area.yview(tk.END)

    def login(self):
        self.username = self.username_entry.get().strip()
        self.server_host = self.server_ip_entry.get().strip()
        server_port = self.server_port_entry.get().strip()
        if not self.username:
            messagebox.showerror("错误", "请输入用户名")
            return
        try:
            self.server_port = int(server_port)
        except ValueError:
            messagebox.showerror("错误", "端口号必须是数字")
            return
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.server_host, self.server_port))
            username_encoded = enc(self.username)
            self.client_socket.send(username_encoded.encode('utf-8'))
            welcome_encoded = self.client_socket.recv(1024).decode('utf-8')
            welcome = dec(welcome_encoded)
            self.create_chat_ui()
            self.display_system_message(welcome)
        except Exception as e:
            messagebox.showerror("连接失败", f"无法连接到服务器: {str(e)}")

    def display_system_message(self, message):
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.insert(tk.END, f"{message}\n", "system")
        self.chat_area.config(state=tk.DISABLED)
        self.chat_area.yview(tk.END)

    def display_user_message(self, username, message, is_self=False):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        tag = "self" if is_self else "other"
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.insert(tk.END, f"{username} ({timestamp}):\n", tag)
        self.chat_area.insert(tk.END, f"{message}\n\n", tag)
        self.chat_area.config(state=tk.DISABLED)
        self.chat_area.yview(tk.END)

    def receive_messages(self):
        buffer = ""
        while self.running:
            try:
                data_encoded = self.client_socket.recv(8192).decode('utf-8')
                if not data_encoded:
                    self.display_system_message("[!] 与服务器的连接已断开")
                    self.running = False
                    break
                buffer += data_encoded
                while buffer:
                    try:
                        data = dec(buffer)
                        if "|" in data:
                            parts = data.split("|")
                            for part in parts:
                                self.process_server_message(part)
                        else:
                            self.process_server_message(data)
                        buffer = ""
                    except base64.binascii.Error:
                        break
                    except Exception as e:
                        self.display_system_message(f"[!] 消息解码失败: {str(e)}")
                        buffer = ""
                        continue
            except Exception as e:
                if self.running:
                    self.display_system_message(f"[!] 接收消息错误: {str(e)}")
                self.running = False
                break

    def process_server_message(self, data):
        if data.startswith("SESSION_LIST:"):
            sessions_str = data[len("SESSION_LIST:"):]
            sessions = sessions_str.split(",") if sessions_str else []
            self.update_session_list(sessions)
        elif data.startswith("USER_LIST:"):
            users_str = data[len("USER_LIST:"):]
            users = [user for user in users_str.split(",") if user] if users_str else []
            self.update_user_list(users)
        elif data.startswith("SESSION_JOINED:"):
            session_id = data.split(":")[1]
            self.current_session = session_id
            self.chat_title.config(text=f"当前会话: {session_id}")
            self.display_system_message(f"您已加入会话: {session_id}")
        elif data.startswith("SESSION_LEFT:"):
            session_id = data.split(":")[1]
            self.current_session = None
            self.chat_title.config(text="未加入会话")
            self.display_system_message(f"您已离开会话: {session_id}")
        elif data.startswith("SYSTEM:"):
            self.display_system_message(data[7:])
        elif data.startswith("IMAGE:") or data.startswith("FILE:"):
            try:
                file_type = "IMAGE" if data.startswith("IMAGE:") else "FILE"
                file_info = data[len(file_type) + 1:]
                parts = file_info.split("|", 2)
                if len(parts) < 3:
                    self.display_system_message(f"[!] 无效的{file_type}消息格式")
                    return
                sender = parts[0].strip()
                filename = parts[1].strip()
                file_data = parts[2].strip()
                if file_type == "IMAGE":
                    self.display_image(sender, filename, file_data)
                else:
                    self.receive_file(sender, filename, file_data)
            except Exception as e:
                self.display_system_message(f"[!] {file_type}接收失败: {str(e)}")
        elif data.startswith("VOICE:"):
            try:
                file_info = data[len("VOICE:"):]
                parts = file_info.split("|", 2)
                if len(parts) < 3:
                    self.display_system_message("[!] 无效的VOICE消息格式")
                    return
                sender, filename, file_data = parts[0].strip(), parts[1].strip(), parts[2].strip()
                self.display_voice(sender, filename, file_data)
            except Exception as e:
                self.display_system_message(f"[!] 语音消息处理失败: {str(e)}")
        else:
            if data.startswith("[") and "]" in data:
                username_end = data.index("]")
                username = data[1:username_end]
                message = data[username_end + 2:]
                self.display_user_message(username, message)
            else:
                self.display_user_message("未知用户", data)

    def update_session_list(self, sessions):
        self.session_listbox.delete(0, tk.END)
        for session in sessions:
            if session:
                self.session_listbox.insert(tk.END, session)
        session_count = len(sessions)
        self.session_list_frame.config(text=f"可用会话 ({session_count})")
        self.last_list_update = time.time()

    def update_user_list(self, users):
        self.user_listbox.delete(0, tk.END)
        for user in users:
            if user:
                self.user_listbox.insert(tk.END, user)
        user_count = len(users)
        self.user_list_frame.config(text=f"在线用户 ({user_count})")
        self.last_list_update = time.time()

    def send_command(self, command):
        try:
            command_encoded = enc(command)
            self.client_socket.send(command_encoded.encode('utf-8'))
        except Exception as e:
            self.display_system_message(f"[!] 发送命令失败: {str(e)}")
            self.running = False

    def send_message(self, event=None):
        message = self.message_entry.get().strip()
        if not message:
            return
        self.message_entry.delete(0, tk.END)
        self.display_user_message(self.username, message, is_self=True)
        self.send_command(message)

    def create_session(self):
        session_id = simpledialog.askstring("创建会话", "请输入会话ID:", parent=self.root)
        if session_id:
            self.send_command(f"CREATE {session_id}")
            self.current_session = session_id
            self.chat_title.config(text=f"当前会话: {session_id}")

    def join_session(self):
        join_window = tk.Toplevel(self.root)
        join_window.title("加入会话")
        join_window.geometry("400x300")
        join_window.transient(self.root)
        join_window.grab_set()
        sessions = [self.session_listbox.get(idx) for idx in range(self.session_listbox.size())]
        if not sessions:
            tk.Label(join_window, text="当前没有可用会话", padx=20, pady=20).pack()
            tk.Button(join_window, text="确定", command=join_window.destroy).pack(pady=10)
            return
        list_frame = tk.Frame(join_window)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        tk.Label(list_frame, text="请选择要加入的会话:", anchor="w").pack(fill=tk.X)
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        session_list = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, selectmode=tk.SINGLE)
        session_list.pack(fill=tk.BOTH, expand=True, pady=5)
        scrollbar.config(command=session_list.yview)
        for session in sessions:
            session_list.insert(tk.END, session)
        if sessions:
            session_list.select_set(0)
            session_list.see(0)
        btn_frame = tk.Frame(join_window)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        def on_join():
            selected = session_list.curselection()
            if selected:
                session_id = session_list.get(selected[0])
                self.send_command(f"JOIN {session_id}")
                self.current_session = session_id
                self.chat_title.config(text=f"当前会话: {session_id}")
                join_window.destroy()
            else:
                messagebox.showwarning("选择会话", "请先选择一个会话", parent=join_window)
        tk.Button(btn_frame, text="加入", command=on_join, width=10).pack(side=tk.RIGHT, padx=5)
        tk.Button(btn_frame, text="取消", command=join_window.destroy, width=10).pack(side=tk.RIGHT)

    def leave_session(self):
        if self.current_session:
            self.send_command("LEAVE")
            self.current_session = None
            self.chat_title.config(text="未加入会话")
        else:
            messagebox.showwarning("离开会话", "您当前没有加入任何会话")

    def refresh_lists(self):
        current_time = time.time()
        if current_time - self.last_list_update < 2:
            self.display_system_message("请勿频繁刷新列表")
            return
        self.send_command("LIST USERS")
        self.display_system_message("列表刷新中...")
        self.last_list_update = current_time

    def on_session_double_click(self, event):
        self.join_session()

    def on_closing(self):
        if messagebox.askokcancel("退出", "确定要退出聊天程序吗？"):
            self.running = False
            try:
                if self.client_socket:
                    if self.current_session:
                        self.send_command("LEAVE")
                    self.client_socket.close()
            except Exception as e:
                print(f"关闭时出错: {str(e)}")
            finally:
                self.root.destroy()

if __name__ == "__main__":
    if sys.platform == "win32":
        try:
            import win_unicode_console
            win_unicode_console.enable()
        except:
            pass
    root = tk.Tk()
    app = ChatClientGUI(root)
    root.mainloop()