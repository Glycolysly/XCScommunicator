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
import re
import webbrowser
import struct

# 配置 - 修改为您的服务器IP
SERVER_HOST = '192.168.1.102'  # 服务器IP
SERVER_PORT = 62599  # 服务器端口

# 自定义Base64编码函数
CUSTOM_ALPHABET = "idhR+nWSPOU0CGIrNmAqVZlYuo2sDt7yg6MBXF1aw4Kv9LHJkjb5p8/zxcefQ3ET"
STANDARD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# 创建转换字典
ENCODE_TRANS = str.maketrans(STANDARD_ALPHABET, CUSTOM_ALPHABET)
DECODE_TRANS = str.maketrans(CUSTOM_ALPHABET, STANDARD_ALPHABET)


def custom_b64encode(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    standard = base64.b64encode(data).decode('utf-8')
    return standard.translate(ENCODE_TRANS)


def custom_b64decode(data):
    standard = data.translate(DECODE_TRANS)
    return base64.b64decode(standard).decode('utf-8')


def enc(data):
    """编码数据"""
    return custom_b64encode(data)


def dec(data):
    """解码数据"""
    return custom_b64decode(data)


# 消息队列用于GUI更新
gui_queue = queue.Queue()


class ChatClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("安全聊天客户端")
        self.root.geometry("900x600")
        self.root.configure(bg="#f0f0f0")
        self.root.minsize(800, 500)

        # 客户端状态
        self.client_socket = None
        self.username = None
        self.current_session = None
        self.running = True
        self.lock = threading.Lock()
        self.recent_sent = []
        self.server_host = SERVER_HOST
        self.server_port = SERVER_PORT
        self.last_list_update = time.time()  # 记录最后一次列表更新时间
        self.image_references = []  # 存储图像引用防止被垃圾回收
        self.file_buffer = {}  # 文件缓冲区 {file_id: [chunks]}
        self.current_file = None  # 当前正在接收的文件信息

        # 创建下载目录
        self.download_dir = os.path.join(os.getcwd(), "downloads")
        os.makedirs(self.download_dir, exist_ok=True)

        # 创建登录界面
        self.create_login_ui()

        # 设置窗口关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_login_ui(self):
        """创建登录界面"""
        self.login_frame = tk.Frame(self.root, bg="#f0f0f0", padx=20, pady=20)
        self.login_frame.pack(expand=True, fill=tk.BOTH)

        # 标题
        title_label = tk.Label(self.login_frame, text="安全聊天客户端",
                               font=("Arial", 24, "bold"), bg="#f0f0f0", fg="#333")
        title_label.pack(pady=20)

        # 服务器信息
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

        # 用户名输入
        user_frame = tk.Frame(self.login_frame, bg="#f0f0f0")
        user_frame.pack(fill=tk.X, pady=10)

        tk.Label(user_frame, text="用户名:", bg="#f0f0f0", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        self.username_entry = tk.Entry(user_frame, width=25, font=("Arial", 10))
        self.username_entry.pack(side=tk.LEFT, padx=5)

        # 登录按钮
        login_btn = tk.Button(self.login_frame, text="登录", command=self.login,
                              bg="#4CAF50", fg="white", font=("Arial", 12), width=15)
        login_btn.pack(pady=20)

        # 提示信息
        info_label = tk.Label(self.login_frame,
                              text="使用说明:\n1. 输入用户名和服务器信息\n2. 登录后可以创建或加入会话\n3. 在消息框中输入消息并发送\n4. 使用表情按钮添加表情符号\n5. 使用文件按钮发送文件",
                              bg="#f0f0f0", fg="#666", justify=tk.LEFT, font=("Arial", 9))
        info_label.pack(pady=10)

        # 设置焦点
        self.username_entry.focus_set()

    def create_chat_ui(self):
        """创建聊天主界面"""
        # 移除登录界面
        self.login_frame.destroy()

        # 创建主框架
        main_frame = tk.Frame(self.root, bg="#f0f0f0")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 左侧会话和用户面板
        left_panel = tk.Frame(main_frame, bg="white", width=200, relief=tk.RAISED, borderwidth=1)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_panel.pack_propagate(False)  # 保持固定宽度

        # 会话管理
        session_frame = tk.LabelFrame(left_panel, text="会话管理", bg="white", padx=5, pady=5)
        session_frame.pack(fill=tk.X, padx=5, pady=5)

        tk.Button(session_frame, text="创建会话", command=self.create_session,
                  bg="#2196F3", fg="white", width=12).pack(side=tk.LEFT, padx=2)
        tk.Button(session_frame, text="加入会话", command=self.join_session,
                  bg="#2196F3", fg="white", width=12).pack(side=tk.LEFT, padx=2)

        tk.Button(session_frame, text="离开会话", command=self.leave_session,
                  bg="#FF9800", fg="white", width=12).pack(side=tk.LEFT, padx=2)

        # 刷新按钮
        tk.Button(session_frame, text="刷新列表", command=self.refresh_lists,
                  bg="#9C27B0", fg="white", width=12).pack(side=tk.LEFT, padx=2)

        # 会话列表
        self.session_list_frame = tk.LabelFrame(left_panel, text="可用会话 (0)", bg="white", padx=5, pady=5)
        self.session_list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.session_listbox = tk.Listbox(self.session_list_frame, bg="white", borderwidth=0,
                                          highlightthickness=0, selectbackground="#e0e0e0")
        scrollbar = tk.Scrollbar(self.session_list_frame, orient="vertical", command=self.session_listbox.yview)
        self.session_listbox.config(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.session_listbox.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        self.session_listbox.bind("<Double-Button-1>", self.on_session_double_click)  # 双击加入会话

        # 用户列表
        self.user_list_frame = tk.LabelFrame(left_panel, text="在线用户 (0)", bg="white", padx=5, pady=5)
        self.user_list_frame.pack(fill=tk.BOTH, padx=5, pady=(0, 5))

        self.user_listbox = tk.Listbox(self.user_list_frame, bg="white", borderwidth=0,
                                       highlightthickness=0, selectbackground="#e0e0e0")
        scrollbar2 = tk.Scrollbar(self.user_list_frame, orient="vertical", command=self.user_listbox.yview)
        self.user_listbox.config(yscrollcommand=scrollbar2.set)

        scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)
        self.user_listbox.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # 右侧聊天区域
        right_panel = tk.Frame(main_frame, bg="white", relief=tk.RAISED, borderwidth=1)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # 聊天标题栏
        self.chat_title = tk.Label(right_panel, text="未加入会话", bg="#e0e0e0", fg="#333",
                                   font=("Segoe UI", 12, "bold"), padx=10, pady=5, anchor=tk.W)
        self.chat_title.pack(fill=tk.X)

        # 聊天消息区域
        self.chat_area = scrolledtext.ScrolledText(
            right_panel,
            bg="white",
            fg="#333",
            font=("Segoe UI", 11),  # 使用更清晰的字体
            padx=10,
            pady=10,
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.chat_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 标签配置 - 使用更清晰的字体
        self.chat_area.tag_config("self", foreground="#0066cc", font=("Segoe UI", 11))
        self.chat_area.tag_config("other", foreground="#333", font=("Segoe UI", 11))
        self.chat_area.tag_config("system", foreground="#666", font=("Segoe UI", 10))
        self.chat_area.tag_config("file", foreground="#009688", font=("Segoe UI", 10))
        self.chat_area.tag_config("filelink", foreground="#1e88e5", font=("Segoe UI", 10, "underline"))
        self.chat_area.tag_config("image", foreground="#4CAF50", font=("Segoe UI", 10))

        # 消息输入区域
        input_frame = tk.Frame(right_panel, bg="#f0f0f0", padx=5, pady=5)
        input_frame.pack(fill=tk.X, padx=5, pady=(0, 5))

        self.message_entry = tk.Entry(input_frame, font=("Segoe UI", 11))  # 优化输入框字体
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.message_entry.bind("<Return>", self.send_message)

        send_btn = tk.Button(input_frame, text="发送", command=self.send_message,
                             bg="#4CAF50", fg="white", width=8, font=("Segoe UI", 10))
        send_btn.pack(side=tk.RIGHT, padx=5)

        # 添加表情按钮
        emoji_btn = tk.Button(input_frame, text="😊", command=self.insert_emoji,
                              font=("Segoe UI", 12), width=2, bg="#f0f0f0", relief=tk.FLAT)
        emoji_btn.pack(side=tk.RIGHT, padx=5)

        # 添加文件按钮
        file_btn = tk.Button(input_frame, text="📁", command=self.send_file,
                             font=("Segoe UI", 12), width=2, bg="#f0f0f0", relief=tk.FLAT)
        file_btn.pack(side=tk.RIGHT, padx=5)

        # 设置焦点
        self.message_entry.focus_set()

        # 启动接收消息线程
        self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        self.receive_thread.start()

        # 初始刷新列表
        self.refresh_lists()

    def on_session_double_click(self, event):
        """双击会话列表加入会话"""
        self.join_session()

    def insert_emoji(self):
        """插入表情符号 - 扩展版"""
        emoji_window = tk.Toplevel(self.root)
        emoji_window.title("选择表情")
        emoji_window.geometry("400x300")
        emoji_window.transient(self.root)
        emoji_window.grab_set()

        # 表情分类
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

        # 创建标签页
        tab_control = ttk.Notebook(emoji_window)

        for category, emojis in emoji_categories.items():
            tab = ttk.Frame(tab_control)
            tab_control.add(tab, text=category)

            # 创建表情按钮网格
            frame = tk.Frame(tab)
            frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            for i, emoji_char in enumerate(emojis):
                row, col = divmod(i, 8)
                btn = tk.Button(frame, text=emoji_char, font=("Segoe UI", 16),  # 优化表情字体
                                command=lambda e=emoji_char: self.select_emoji(e, emoji_window),
                                relief=tk.FLAT, bg="#f0f0f0", width=2)
                btn.grid(row=row, column=col, padx=5, pady=5)

        tab_control.pack(expand=1, fill="both")

    def select_emoji(self, emoji_char, window):
        """选择表情并插入输入框"""
        self.message_entry.insert(tk.INSERT, emoji_char)
        window.destroy()
        self.message_entry.focus_set()

    def send_file(self):
        """发送文件"""
        filepath = filedialog.askopenfilename(
            title="选择要发送的文件",
            filetypes=[("所有文件", "*.*"), ("图片", "*.jpg *.jpeg *.png *.gif"),
                       ("文档", "*.pdf *.doc *.docx *.txt"), ("视频", "*.mp4 *.avi *.mov")]
        )

        if not filepath:
            return

        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)

        # 检查文件大小（限制为10MB）
        MAX_SIZE = 10 * 1024 * 1024  # 10MB
        if filesize > MAX_SIZE:
            messagebox.showerror("文件过大", f"文件大小超过限制 ({filesize // 1024}KB > {MAX_SIZE // 1024}KB)")
            return

        try:
            with open(filepath, "rb") as f:
                file_bytes = f.read()
                file_data = base64.b64encode(file_bytes).decode('utf-8')

            # 发送文件命令（包含发送者信息）
            file_type = "IMAGE" if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')) else "FILE"
            command = f"{file_type}:{self.username}|{filename}|{file_data}"
            self.send_command(command)

            # 在聊天区域显示发送文件消息
            self.display_user_message(self.username, f"发送了文件: {filename}", is_self=True)

        except Exception as e:
            messagebox.showerror("文件错误", f"无法发送文件: {str(e)}")

    def display_image(self, sender, filename, image_data):
        """在聊天区域显示图片"""
        try:
            # 解码图片数据
            image_bytes = base64.b64decode(image_data)

            # 创建PIL图像对象
            image = Image.open(io.BytesIO(image_bytes))

            # 调整图片大小（最大宽度400px）
            width, height = image.size
            max_width = 400
            if width > max_width:
                ratio = max_width / width
                new_height = int(height * ratio)
                image = image.resize((max_width, new_height), Image.LANCZOS)

            # 转换为Tkinter可用的格式
            photo = ImageTk.PhotoImage(image)

            # 保存图片引用防止被垃圾回收
            self.image_references.append(photo)

            # 在聊天区域显示
            self.chat_area.config(state=tk.NORMAL)

            # 添加发送者信息
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            self.chat_area.insert(tk.END, f"{sender} ({timestamp}):\n", "other")
            self.chat_area.insert(tk.END, "发送了图片: ", "image")

            # 创建图片标签
            image_label = tk.Label(self.chat_area, image=photo, bg="white", cursor="hand2")
            image_label.bind("<Button-1>", lambda e: self.open_file(filename, image_bytes))

            # 在文本区域插入图片
            self.chat_area.window_create(tk.END, window=image_label)
            self.chat_area.insert(tk.END, f" {filename}\n\n")
            self.chat_area.config(state=tk.DISABLED)
            self.chat_area.yview(tk.END)

        except Exception as e:
            self.display_system_message(f"显示图片失败: {str(e)}")

    def open_file(self, filename, file_bytes=None):
        """打开文件"""
        # 如果提供了文件数据，先保存到临时文件
        if file_bytes:
            filepath = os.path.join(self.download_dir, filename)

            # 处理文件名冲突
            counter = 1
            base_name, ext = os.path.splitext(filename)
            while os.path.exists(filepath):
                filename = f"{base_name}({counter}){ext}"
                filepath = os.path.join(self.download_dir, filename)
                counter += 1

            # 保存文件
            with open(filepath, "wb") as f:
                f.write(file_bytes)
        else:
            filepath = os.path.join(self.download_dir, filename)

        try:
            # 根据文件类型决定打开方式
            if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                # 如果是图片，尝试在默认查看器中打开
                webbrowser.open(filepath)
            else:
                # 其他文件使用系统默认方式打开
                os.startfile(filepath) if sys.platform == "win32" else os.system(f'open "{filepath}"')
        except Exception as e:
            messagebox.showerror("打开文件失败", f"无法打开文件: {str(e)}")

    def receive_file(self, sender, filename, file_data):
        """接收并保存文件"""
        try:
            # 解码文件内容
            file_bytes = base64.b64decode(file_data)

            # 创建文件路径
            filepath = os.path.join(self.download_dir, filename)

            # 处理文件名冲突
            counter = 1
            base_name, ext = os.path.splitext(filename)
            while os.path.exists(filepath):
                filename = f"{base_name}({counter}){ext}"
                filepath = os.path.join(self.download_dir, filename)
                counter += 1

            # 保存文件
            with open(filepath, "wb") as f:
                f.write(file_bytes)

            # 在聊天区域显示文件接收消息
            self.chat_area.config(state=tk.NORMAL)

            # 添加发送者信息
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            self.chat_area.insert(tk.END, f"{sender} ({timestamp}):\n", "other")

            if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                # 对于图片文件，显示"发送了图片"提示
                self.chat_area.insert(tk.END, "发送了图片: ", "image")
            else:
                # 对于其他文件，显示"发送了文件"提示
                self.chat_area.insert(tk.END, "发送了文件: ", "file")

            # 创建可点击的文件链接
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

    def login(self):
        """登录服务器"""
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

        # 连接到服务器
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.server_host, self.server_port))

            # 发送用户名
            username_encoded = enc(self.username)
            self.client_socket.send(username_encoded.encode('utf-8'))

            # 接收欢迎消息
            welcome_encoded = self.client_socket.recv(1024).decode('utf-8')
            welcome = dec(welcome_encoded)

            # 创建聊天界面
            self.create_chat_ui()

            # 在聊天区域显示欢迎消息
            self.display_system_message(welcome)

        except Exception as e:
            messagebox.showerror("连接失败", f"无法连接到服务器: {str(e)}")

    def display_system_message(self, message):
        """显示系统消息"""
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.insert(tk.END, f"{message}\n", "system")
        self.chat_area.config(state=tk.DISABLED)
        self.chat_area.yview(tk.END)

    def display_user_message(self, username, message, is_self=False):
        """显示用户消息"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        tag = "self" if is_self else "other"

        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.insert(tk.END, f"{username} ({timestamp}):\n", tag)
        self.chat_area.insert(tk.END, f"{message}\n\n", tag)
        self.chat_area.config(state=tk.DISABLED)
        self.chat_area.yview(tk.END)

    def receive_messages(self):
        """接收服务器消息"""
        buffer = ""  # 用于存储可能不完整的消息
        while self.running:
            try:
                # 接收数据
                data_encoded = self.client_socket.recv(8192).decode('utf-8')  # 增加缓冲区大小
                if not data_encoded:
                    self.display_system_message("[!] 与服务器的连接已断开")
                    self.running = False
                    break

                # 添加到缓冲区
                buffer += data_encoded

                # 处理缓冲区中的所有完整消息
                while buffer:
                    # 尝试解码数据
                    try:
                        # 尝试解码整个缓冲区
                        data = dec(buffer)

                        # 处理组合消息（如果包含分隔符）
                        if "|" in data:
                            parts = data.split("|")
                            for part in parts:
                                self.process_server_message(part)
                        else:
                            self.process_server_message(data)

                        # 重置缓冲区
                        buffer = ""
                    except base64.binascii.Error:
                        # 如果解码失败，可能是消息不完整，等待更多数据
                        break
                    except Exception as e:
                        self.display_system_message(f"[!] 消息解码失败: {str(e)}")
                        buffer = ""
                        continue

            except Exception as e:
                if self.running:  # 避免在关闭时显示错误
                    self.display_system_message(f"[!] 接收消息错误: {str(e)}")
                self.running = False
                break

    def process_server_message(self, data):
        """处理服务器消息"""
        if data.startswith("SESSION_LIST:"):
            # 更新会话列表
            sessions_str = data[len("SESSION_LIST:"):]
            sessions = sessions_str.split(",") if sessions_str else []
            self.update_session_list(sessions)
        elif data.startswith("USER_LIST:"):
            # 更新用户列表
            users_str = data[len("USER_LIST:"):]
            # 过滤空用户
            users = [user for user in users_str.split(",") if user] if users_str else []
            self.update_user_list(users)
        elif data.startswith("SESSION_JOINED:"):
            # 加入会话成功
            session_id = data.split(":")[1]
            self.current_session = session_id
            self.chat_title.config(text=f"当前会话: {session_id}")
            self.display_system_message(f"您已加入会话: {session_id}")
        elif data.startswith("SESSION_LEFT:"):
            # 离开会话
            session_id = data.split(":")[1]
            self.current_session = None
            self.chat_title.config(text="未加入会话")
            self.display_system_message(f"您已离开会话: {session_id}")
        elif data.startswith("SYSTEM:"):
            # 系统消息
            self.display_system_message(data[7:])
        elif data.startswith("IMAGE:") or data.startswith("FILE:"):
            # 文件或图片传输消息
            try:
                # 提取消息类型 (IMAGE 或 FILE)
                file_type = "IMAGE" if data.startswith("IMAGE:") else "FILE"

                # 移除类型前缀
                file_info = data[len(file_type) + 1:]

                # 分割发送者、文件名和文件数据
                parts = file_info.split("|", 2)
                if len(parts) < 3:
                    self.display_system_message(f"[!] 无效的{file_type}消息格式")
                    return

                sender = parts[0].strip()
                filename = parts[1].strip()
                file_data = parts[2].strip()

                # 根据文件类型处理
                if file_type == "IMAGE":
                    # 在聊天区域显示图片
                    self.display_image(sender, filename, file_data)
                else:
                    # 接收并保存文件
                    self.receive_file(sender, filename, file_data)

            except Exception as e:
                self.display_system_message(f"[!] {file_type}接收失败: {str(e)}")
        else:
            # 普通用户消息
            # 解析消息格式: [username] message
            if data.startswith("[") and "]" in data:
                username_end = data.index("]")
                username = data[1:username_end]
                message = data[username_end + 2:]
                self.display_user_message(username, message)
            else:
                self.display_user_message("未知用户", data)

    def update_session_list(self, sessions):
        """更新会话列表"""
        self.session_listbox.delete(0, tk.END)

        # 添加会话到列表
        for session in sessions:
            if session:  # 跳过空会话
                self.session_listbox.insert(tk.END, session)

        # 显示会话数量
        session_count = len(sessions)
        # 修复：正确更新LabelFrame的标题
        self.session_list_frame.config(text=f"可用会话 ({session_count})")

        # 更新最后更新时间
        self.last_list_update = time.time()

    def update_user_list(self, users):
        """更新用户列表"""
        self.user_listbox.delete(0, tk.END)

        # 添加用户到列表
        for user in users:
            if user:  # 跳过空用户
                self.user_listbox.insert(tk.END, user)

        # 显示用户数量
        user_count = len(users)
        # 修复：正确更新LabelFrame的标题
        self.user_list_frame.config(text=f"在线用户 ({user_count})")

        # 更新最后更新时间
        self.last_list_update = time.time()

    def send_command(self, command):
        """发送命令到服务器"""
        try:
            # 编码命令
            command_encoded = enc(command)
            # 发送命令
            self.client_socket.send(command_encoded.encode('utf-8'))
        except Exception as e:
            self.display_system_message(f"[!] 发送命令失败: {str(e)}")
            self.running = False

    def send_message(self, event=None):
        """发送消息"""
        message = self.message_entry.get().strip()
        if not message:
            return

        # 清除输入框
        self.message_entry.delete(0, tk.END)

        # 显示自己的消息
        self.display_user_message(self.username, message, is_self=True)

        # 发送消息到服务器
        self.send_command(message)

    def create_session(self):
        """创建新会话"""
        session_id = simpledialog.askstring("创建会话", "请输入会话ID:", parent=self.root)
        if session_id:
            self.send_command(f"CREATE {session_id}")
            self.current_session = session_id
            self.chat_title.config(text=f"当前会话: {session_id}")

    def join_session(self):
        """加入现有会话 - 弹出窗口选择"""
        # 创建一个新窗口
        join_window = tk.Toplevel(self.root)
        join_window.title("加入会话")
        join_window.geometry("400x300")
        join_window.transient(self.root)
        join_window.grab_set()

        # 获取当前会话列表
        sessions = [self.session_listbox.get(idx) for idx in range(self.session_listbox.size())]

        if not sessions:
            tk.Label(join_window, text="当前没有可用会话", padx=20, pady=20).pack()
            tk.Button(join_window, text="确定", command=join_window.destroy).pack(pady=10)
            return

        # 创建列表框
        list_frame = tk.Frame(join_window)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 添加标题
        tk.Label(list_frame, text="请选择要加入的会话:", anchor="w").pack(fill=tk.X)

        # 创建滚动条
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 创建列表框
        session_list = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, selectmode=tk.SINGLE)
        session_list.pack(fill=tk.BOTH, expand=True, pady=5)
        scrollbar.config(command=session_list.yview)

        # 添加会话到列表框
        for session in sessions:
            session_list.insert(tk.END, session)

        # 默认选择第一个会话
        if sessions:
            session_list.select_set(0)
            session_list.see(0)

        # 添加按钮
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
        """离开当前会话"""
        if self.current_session:
            self.send_command("LEAVE")
            self.current_session = None
            self.chat_title.config(text="未加入会话")
        else:
            messagebox.showwarning("离开会话", "您当前没有加入任何会话")

    def refresh_lists(self):
        """刷新会话和用户列表"""
        # 检查是否过于频繁刷新
        current_time = time.time()
        if current_time - self.last_list_update < 2:  # 2秒内只能刷新一次
            self.display_system_message("请勿频繁刷新列表")
            return

        # 同时请求会话列表和用户列表
        self.send_command("LIST USERS")
        self.display_system_message("列表刷新中...")
        self.last_list_update = current_time

    def on_closing(self):
        """窗口关闭事件处理"""
        if messagebox.askokcancel("退出", "确定要退出聊天程序吗？"):
            self.running = False
            try:
                if self.client_socket:
                    # 离开当前会话
                    if self.current_session:
                        self.send_command("LEAVE")
                    # 关闭套接字
                    self.client_socket.close()
            except Exception as e:
                print(f"关闭时出错: {str(e)}")
            finally:
                self.root.destroy()


if __name__ == "__main__":
    # 对于Windows系统，启用Unicode支持
    if sys.platform == "win32":
        try:
            import win_unicode_console

            win_unicode_console.enable()
        except:
            pass

    # 创建主窗口
    root = tk.Tk()
    app = ChatClientGUI(root)
    root.mainloop()