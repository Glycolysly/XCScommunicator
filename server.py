import socket
import threading
import datetime
import os
import time
import base64
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import queue
import re

ip = socket.gethostbyname(socket.gethostname())
print(ip)
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 62599
MAX_CLIENTS = 20
LOG_FILE = "server_log.txt"
BROADCAST_INTERVAL = 5  # 每隔5秒广播一次列表
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB文件大小限制

# 创建日志目录
if not os.path.exists("logs"):
    os.makedirs("logs")

# 全局数据结构
sessions = {}  # 格式: {session_id: {'creator': creator_socket, 'members': {socket: username}}}
clients = {}  # 格式: {socket: {'username': username, 'session': session_id}}
lock = threading.Lock()  # 用于同步访问共享数据的锁

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


def log_message(client_addr, message, direction):
    """记录通信日志"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} | {client_addr} | {direction}: {message}"

    # 添加到GUI日志队列
    gui_queue.put(("log", f"{log_entry}\n"))

    # 写入日志文件
    with open(f"logs/{LOG_FILE}", "a", encoding='utf-8') as f:
        f.write(f"{log_entry}\n")


def broadcast_lists():
    """定期向所有客户端广播会话列表和用户列表"""
    while broadcast_running:
        try:
            with lock:
                # 收集所有会话ID
                session_ids = list(sessions.keys())
                session_list_msg = "SESSION_LIST:" + ",".join(session_ids)

                # 收集所有在线用户名（过滤空值）
                user_names = [info['username'] for info in clients.values() if info.get('username')]
                user_list_msg = "USER_LIST:" + ",".join(user_names)

                # 组合成一个消息发送
                combined_msg = session_list_msg + "|" + user_list_msg

                # 发送给所有在线客户端
                for client_socket in list(clients.keys()):
                    try:
                        # 编码并发送组合消息
                        combined_encoded = enc(combined_msg)
                        client_socket.send(combined_encoded.encode('utf-8'))
                    except:
                        # 发送失败，可能是连接已断开
                        pass

                # 更新服务器GUI
                gui_queue.put(("sessions", list(sessions.keys())))
                gui_queue.put(("clients", list(clients.values())))

        except Exception as e:
            log_message("SERVER", f"广播列表错误: {str(e)}", "错误")

        # 等待下一次广播
        time.sleep(BROADCAST_INTERVAL)


def handle_client(client_socket, client_address):
    """处理单个客户端连接"""
    log_message(client_address, f"客户端已连接", "连接")
    username = None
    current_session = None

    try:
        # 接收用户名 (使用UTF-8解码)
        username_encoded = client_socket.recv(1024).decode('utf-8')
        if not username_encoded:
            return

        # 解码用户名
        try:
            username = dec(username_encoded).strip()
        except Exception as e:
            log_message(client_address, f"用户名解码失败: {str(e)}", "错误")
            client_socket.close()
            return

        log_message(client_address, f"用户 '{username}' 登录", "登录")

        # 添加到全局客户端列表
        with lock:
            clients[client_socket] = {
                'username': username,
                'session': None,
                'address': client_address,
                'login_time': datetime.datetime.now()
            }
            gui_queue.put(("clients", list(clients.values())))

        # 发送欢迎消息 (使用UTF-8编码)
        welcome_msg = f"欢迎, {username}! 😊 请选择操作:\n" \
                      "1. 创建新会话 (输入: CREATE <会话ID>)\n" \
                      "2. 加入现有会话 (输入: JOIN <会话ID>)\n" \
                      "3. 查看所有会话和用户 (输入: LIST)"

        # 编码欢迎消息
        welcome_encoded = enc(welcome_msg)
        client_socket.send(welcome_encoded.encode('utf-8'))

        while True:
            # 接收客户端指令 (使用UTF-8解码)
            command_encoded = client_socket.recv(8192).decode('utf-8').strip()  # 增加缓冲区大小
            if not command_encoded:
                break

            # 解码命令
            try:
                command = dec(command_encoded)
            except Exception as e:
                log_message(client_address, f"命令解码失败: {str(e)}", "错误")
                continue

            log_message(client_address, command, "接收")

            # 处理命令
            if command.startswith("CREATE "):
                session_id = command.split(" ", 1)[1].strip()
                with lock:
                    if session_id in sessions:
                        response = f"错误: 会话ID '{session_id}' 已存在 😅"
                    else:
                        sessions[session_id] = {
                            'creator': client_socket,
                            'members': {client_socket: username},
                            'created': datetime.datetime.now()
                        }
                        clients[client_socket]['session'] = session_id
                        current_session = session_id
                        response = f"成功创建会话 '{session_id}'! 🎉 等待其他用户加入..."
                        log_message(client_address, f"用户 '{username}' 创建了会话 '{session_id}'", "创建会话")
                        gui_queue.put(("sessions", list(sessions.keys())))
                        gui_queue.put(("clients", list(clients.values())))

                # 编码响应
                response_encoded = enc(response)
                client_socket.send(response_encoded.encode('utf-8'))

            elif command.startswith("JOIN "):
                session_id = command.split(" ", 1)[1].strip()
                with lock:
                    if session_id in sessions:
                        # 添加到会话
                        sessions[session_id]['members'][client_socket] = username
                        clients[client_socket]['session'] = session_id
                        current_session = session_id

                        # 通知会话成员有新用户加入
                        join_msg = f"[系统] 用户 '{username}' 加入了会话 👋"
                        broadcast_message(session_id, join_msg, exclude=client_socket)

                        response = f"成功加入会话 '{session_id}'! 👍 当前成员: " + \
                                   ", ".join(sessions[session_id]['members'].values())
                        log_message(client_address, f"用户 '{username}' 加入了会话 '{session_id}'", "加入会话")
                        gui_queue.put(("clients", list(clients.values())))
                    else:
                        response = f"错误: 会话ID '{session_id}' 不存在 😕"

                # 编码响应
                response_encoded = enc(response)
                client_socket.send(response_encoded.encode('utf-8'))

            elif command == "LIST" or command == "LIST USERS":
                with lock:
                    if sessions:
                        response = "当前活跃会话:\n" + "\n".join([
                            f" - {session_id} ({len(members['members'])} 名成员)"
                            for session_id, members in sessions.items()
                        ])
                    else:
                        response = "当前没有活跃会话"

                    # 添加用户列表信息
                    user_names = [info['username'] for info in clients.values() if info.get('username')]
                    if user_names:
                        response += "\n\n当前在线用户:\n" + "\n".join([
                            f" - {username}" for username in user_names
                        ])
                    else:
                        response += "\n\n当前没有其他在线用户"

                # 编码响应
                response_encoded = enc(response)
                client_socket.send(response_encoded.encode('utf-8'))

            elif command == "LEAVE":
                if current_session:
                    with lock:
                        if current_session in sessions:
                            # 从会话中移除
                            if client_socket in sessions[current_session]['members']:
                                del sessions[current_session]['members'][client_socket]

                            # 如果会话为空则删除
                            if not sessions[current_session]['members']:
                                del sessions[current_session]
                                log_message(client_address, f"会话 '{current_session}' 已关闭", "会话关闭")
                                gui_queue.put(("sessions", list(sessions.keys())))

                            # 通知其他成员
                            leave_msg = f"[系统] 用户 '{username}' 离开了会话 👋"
                            broadcast_message(current_session, leave_msg, exclude=client_socket)

                            response = f"你已离开会话 '{current_session}' 👋"
                            current_session = None
                            clients[client_socket]['session'] = None
                            gui_queue.put(("clients", list(clients.values())))
                        else:
                            response = "错误: 你不在任何会话中 😕"
                else:
                    response = "错误: 你不在任何会话中 😕"

                # 编码响应
                response_encoded = enc(response)
                client_socket.send(response_encoded.encode('utf-8'))


            elif command.startswith("IMAGE:") or command.startswith("FILE:"):

                if current_session:

                    with lock:

                        if current_session in sessions:

                            # 提取消息类型 (IMAGE 或 FILE)

                            file_type = "IMAGE" if command.startswith("IMAGE:") else "FILE"

                            # 移除类型前缀

                            file_info = command[len(file_type) + 1:]

                            # 分割发送者、文件名和文件数据

                            parts = file_info.split("|", 2)

                            if len(parts) < 3:
                                response = f"错误: 无效的{file_type}消息格式"

                                response_encoded = enc(response)

                                client_socket.send(response_encoded.encode('utf-8'))

                                continue

                            sender = parts[0].strip()

                            filename = parts[1].strip()

                            file_data = parts[2].strip()

                            # 精确计算文件大小 (Base64解码后)

                            file_size = (len(file_data) * 3) // 4  # Base64解码后近似大小

                            if file_size > MAX_FILE_SIZE:

                                response = "错误: 文件大小超过10MB限制"

                                response_encoded = enc(response)

                                client_socket.send(response_encoded.encode('utf-8'))

                            else:

                                # 重构消息格式：类型|发送者|文件名|文件数据

                                safe_message = f"{file_type}:{sender}|{filename}|{file_data}"

                                # 广播重构后的安全格式

                                broadcast_message(current_session, safe_message, exclude=client_socket)

                                log_message(client_address, f"转发{file_type}: {filename}", "转发")

                        else:

                            response = "错误: 你不在任何会话中 😕"

                            response_encoded = enc(response)

                            client_socket.send(response_encoded.encode('utf-8'))

                else:

                    response = "请先创建或加入一个会话 😊"

                    response_encoded = enc(response)

                    client_socket.send(response_encoded.encode('utf-8'))

            elif current_session:
                # 如果用户已加入会话，则转发消息给会话成员
                with lock:
                    if current_session in sessions:
                        # 转发消息
                        broadcast_message(current_session, f"[{username}]: {command}", exclude=client_socket)
                        log_message(client_address, f"转发消息: {command}", "转发")
                    else:
                        response = "错误: 你不在任何会话中 😕"
                        # 编码响应
                        response_encoded = enc(response)
                        client_socket.send(response_encoded.encode('utf-8'))
            else:
                # 未加入会话时的默认响应
                response = "请先创建或加入一个会话 (CREATE, JOIN, LIST) 😊"
                # 编码响应
                response_encoded = enc(response)
                client_socket.send(response_encoded.encode('utf-8'))

    except ConnectionResetError:
        log_message(client_address, "客户端异常断开", "错误")
    except Exception as e:
        log_message(client_address, f"处理客户端错误: {str(e)}", "错误")
    finally:
        # 清理客户端
        with lock:
            # 从会话中移除
            if client_socket in clients and clients[client_socket]['session']:
                session_id = clients[client_socket]['session']
                if session_id in sessions and client_socket in sessions[session_id]['members']:
                    del sessions[session_id]['members'][client_socket]

                    # 如果会话为空则删除
                    if not sessions[session_id]['members']:
                        del sessions[session_id]
                        log_message(client_address, f"会话 '{session_id}' 已关闭", "会话关闭")
                        gui_queue.put(("sessions", list(sessions.keys())))

            # 从全局客户端列表中移除
            if client_socket in clients:
                del clients[client_socket]
                gui_queue.put(("clients", list(clients.values())))

        client_socket.close()
        log_message(client_address, "客户端连接关闭", "断开")


def broadcast_message(session_id, message, exclude=None):
    """向会话中的所有成员广播消息（排除指定成员）"""
    if session_id not in sessions:
        return

    # 编码消息
    try:
        message_encoded = enc(message)
    except Exception as e:
        log_message("SERVER", f"广播消息编码失败: {str(e)}", "错误")
        return

    for member_socket in sessions[session_id]['members']:
        if member_socket != exclude:  # 排除消息发送者
            try:
                # 确保使用UTF-8编码发送
                member_socket.send(message_encoded.encode('utf-8'))
            except:
                # 发送失败，可能是连接已断开
                pass


class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("聊天服务器管理控制台")
        self.root.geometry("1200x800")
        self.root.configure(bg="#f0f0f0")

        # 服务器状态
        self.server_running = False
        self.server_thread = None
        self.server_socket = None
        self.broadcast_thread = None
        global broadcast_running
        broadcast_running = False

        # 创建UI
        self.create_ui()

        # 设置窗口关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # 启动GUI更新循环
        self.update_gui()

    def create_ui(self):
        """创建用户界面"""
        # 顶部控制面板
        control_frame = tk.Frame(self.root, bg="#e0e0e0", padx=10, pady=10)
        control_frame.pack(fill=tk.X)

        # 服务器状态标签
        self.status_label = tk.Label(control_frame, text="服务器状态: 停止",
                                     bg="#e0e0e0", fg="#d32f2f", font=("Arial", 12, "bold"))
        self.status_label.pack(side=tk.LEFT, padx=10)

        # 启动按钮
        self.start_btn = tk.Button(control_frame, text="启动服务器", command=self.start_server,
                                   bg="#4CAF50", fg="white", font=("Arial", 10), width=12)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        # 停止按钮
        self.stop_btn = tk.Button(control_frame, text="停止服务器", command=self.stop_server,
                                  bg="#f44336", fg="white", font=("Arial", 10), width=12, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        # 清空日志按钮
        clear_btn = tk.Button(control_frame, text="清空日志", command=self.clear_logs,
                              bg="#2196F3", fg="white", font=("Arial", 10), width=10)
        clear_btn.pack(side=tk.RIGHT, padx=5)

        # 刷新按钮
        refresh_btn = tk.Button(control_frame, text="刷新数据", command=self.refresh_data,
                                bg="#9C27B0", fg="white", font=("Arial", 10), width=10)
        refresh_btn.pack(side=tk.RIGHT, padx=5)

        # 主内容区域
        main_frame = tk.Frame(self.root, bg="#f0f0f0")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 左侧面板（会话和用户）
        left_panel = tk.Frame(main_frame, bg="white", width=300, relief=tk.RAISED, borderwidth=1)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_panel.pack_propagate(False)

        # 会话列表
        session_frame = tk.LabelFrame(left_panel, text="活跃会话", bg="white", padx=5, pady=5)
        session_frame.pack(fill=tk.BOTH, padx=5, pady=5)

        # 会话列表树状图
        self.session_tree = ttk.Treeview(session_frame, columns=("creator", "members", "created"), show="headings")
        self.session_tree.heading("#0", text="会话ID")
        self.session_tree.heading("creator", text="创建者")
        self.session_tree.heading("members", text="成员数")
        self.session_tree.heading("created", text="创建时间")
        self.session_tree.column("#0", width=120)
        self.session_tree.column("creator", width=100)
        self.session_tree.column("members", width=60, anchor=tk.CENTER)
        self.session_tree.column("created", width=80, anchor=tk.CENTER)

        scrollbar = ttk.Scrollbar(session_frame, orient="vertical", command=self.session_tree.yview)
        self.session_tree.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.session_tree.pack(fill=tk.BOTH, expand=True)

        # 用户列表
        user_frame = tk.LabelFrame(left_panel, text="在线用户", bg="white", padx=5, pady=5)
        user_frame.pack(fill=tk.BOTH, padx=5, pady=(0, 5))

        # 用户列表树状图
        self.user_tree = ttk.Treeview(user_frame, columns=("session", "address", "login_time"), show="headings")
        self.user_tree.heading("#0", text="用户名")
        self.user_tree.heading("session", text="所在会话")
        self.user_tree.heading("address", text="IP地址")
        self.user_tree.heading("login_time", text="登录时间")
        self.user_tree.column("#0", width=100)
        self.user_tree.column("session", width=100)
        self.user_tree.column("address", width=120)
        self.user_tree.column("login_time", width=100)

        scrollbar2 = ttk.Scrollbar(user_frame, orient="vertical", command=self.user_tree.yview)
        self.user_tree.configure(yscrollcommand=scrollbar2.set)

        scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)
        self.user_tree.pack(fill=tk.BOTH, expand=True)

        # 右侧日志面板
        log_frame = tk.LabelFrame(main_frame, text="服务器日志", bg="white", padx=5, pady=5)
        log_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # 日志文本框
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            bg="white",
            fg="#333",
            font=("Consolas", 10),
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 添加标签配置
        self.log_text.tag_config("info", foreground="blue")
        self.log_text.tag_config("error", foreground="red")
        self.log_text.tag_config("warning", foreground="orange")
        self.log_text.tag_config("success", foreground="green")

        # 添加初始日志
        self.add_log("服务器管理控制台已启动", "info")
        self.add_log(f"服务器IP: {SERVER_HOST}, 端口: {SERVER_PORT}", "info")
        self.add_log("点击'启动服务器'按钮开始服务", "info")

    def start_server(self):
        """启动服务器"""
        if self.server_running:
            self.add_log("服务器已在运行中", "warning")
            return

        try:
            # 清空全局数据结构
            global sessions, clients, broadcast_running
            with lock:
                sessions.clear()
                clients.clear()

            # 创建服务器线程
            self.server_thread = threading.Thread(target=self.run_server, daemon=True)
            self.server_running = True
            self.server_thread.start()

            # 启动广播线程
            broadcast_running = True
            self.broadcast_thread = threading.Thread(target=broadcast_lists, daemon=True)
            self.broadcast_thread.start()

            # 更新UI状态
            self.status_label.config(text="服务器状态: 运行中", fg="#388E3C")
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)

            self.add_log(f"服务器已启动在 {SERVER_HOST}:{SERVER_PORT}", "success")
            self.add_log(f"广播线程已启动，每{BROADCAST_INTERVAL}秒发送一次列表", "info")

        except Exception as e:
            self.add_log(f"启动服务器失败: {str(e)}", "error")
            self.server_running = False

    def run_server(self):
        """运行服务器线程"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((SERVER_HOST, SERVER_PORT))
        self.server_socket.listen(MAX_CLIENTS)

        # 清空日志文件
        open(f"logs/{LOG_FILE}", "w", encoding='utf-8').close()

        try:
            while self.server_running:
                client_socket, client_address = self.server_socket.accept()

                # 创建新线程处理客户端连接
                client_thread = threading.Thread(
                    target=handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()

        except Exception as e:
            if self.server_running:  # 避免在正常停止时记录错误
                self.add_log(f"服务器错误: {str(e)}", "error")
        finally:
            self.server_socket.close()
            self.server_running = False

    def stop_server(self):
        """停止服务器"""
        if not self.server_running:
            self.add_log("服务器未运行", "warning")
            return

        global broadcast_running
        broadcast_running = False
        self.server_running = False

        # 关闭服务器套接字以中断accept调用
        try:
            self.server_socket.close()
        except:
            pass

        # 关闭所有客户端连接
        with lock:
            for client_socket in list(clients.keys()):
                try:
                    client_socket.close()
                except:
                    pass
            clients.clear()
            sessions.clear()

        # 更新UI状态
        self.status_label.config(text="服务器状态: 停止", fg="#d32f2f")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

        self.add_log("服务器已停止", "info")

        # 清空会话和用户列表
        self.session_tree.delete(*self.session_tree.get_children())
        self.user_tree.delete(*self.user_tree.get_children())

    def add_log(self, message, tag="info"):
        """添加日志到文本区域"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] {message}\n"

        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, formatted_msg, tag)
        self.log_text.config(state=tk.DISABLED)
        self.log_text.yview(tk.END)

    def update_sessions(self, session_list):
        """更新会话列表"""
        self.session_tree.delete(*self.session_tree.get_children())

        with lock:
            for session_id in session_list:
                session = sessions.get(session_id)
                if session:
                    # 获取创建者用户名
                    creator_socket = session['creator']
                    creator = clients.get(creator_socket, {}).get('username', '未知')

                    members = len(session['members'])
                    created = session['created'].strftime("%H:%M:%S")

                    self.session_tree.insert("", "end", text=session_id,
                                             values=(creator, members, created))

    def update_clients(self, client_list):
        """更新用户列表"""
        self.user_tree.delete(*self.user_tree.get_children())

        for client in client_list:
            username = client.get('username', '未知')
            session = client.get('session', '无') or "无"
            address = f"{client.get('address', ('未知',))[0]}"
            login_time = client.get('login_time', datetime.datetime.now()).strftime("%H:%M:%S")

            self.user_tree.insert("", "end", text=username,
                                  values=(session, address, login_time))

    def update_gui(self):
        """定期更新GUI"""
        try:
            while not gui_queue.empty():
                item_type, data = gui_queue.get_nowait()

                if item_type == "log":
                    # 日志消息格式: [时间] | 地址 | 方向: 消息
                    parts = data.split("|")
                    if len(parts) >= 3:
                        timestamp = parts[0].strip()
                        address = parts[1].strip()
                        direction_msg = parts[2].strip()

                        # 提取方向
                        direction = direction_msg.split(":", 1)[0].strip()
                        message = direction_msg.split(":", 1)[1].strip() if ":" in direction_msg else direction_msg

                        # 根据方向添加不同标签
                        if "错误" in direction:
                            tag = "error"
                        elif "连接" in direction or "断开" in direction:
                            tag = "warning"
                        elif "登录" in direction or "创建" in direction or "加入" in direction:
                            tag = "success"
                        else:
                            tag = "info"

                        self.log_text.config(state=tk.NORMAL)
                        self.log_text.insert(tk.END, data, tag)
                        self.log_text.config(state=tk.DISABLED)
                        self.log_text.yview(tk.END)

                elif item_type == "sessions":
                    self.update_sessions(data)

                elif item_type == "clients":
                    self.update_clients(data)

        except queue.Empty:
            pass

        # 每100毫秒检查一次更新
        self.root.after(100, self.update_gui)

    def clear_logs(self):
        """清空日志文本框"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.add_log("日志已清空", "info")

    def refresh_data(self):
        """手动刷新会话和用户数据"""
        with lock:
            gui_queue.put(("sessions", list(sessions.keys())))
            gui_queue.put(("clients", list(clients.values())))
        self.add_log("数据已刷新", "info")

    def on_closing(self):
        """窗口关闭事件处理"""
        if self.server_running:
            self.stop_server()
        self.root.destroy()


def start_server_gui():
    """启动带GUI的服务器"""
    root = tk.Tk()
    app = ServerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    # 全局广播控制变量
    broadcast_running = False
    start_server_gui()