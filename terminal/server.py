import socket
import threading
import datetime
import os
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import queue

# 导入功能函数与全局变量
from server_utils import (
    rc4, enc, dec, custom_b64encode, custom_b64decode, RC4_KEY,
    ENCODE_TRANS, DECODE_TRANS, CUSTOM_ALPHABET, STANDARD_ALPHABET,
    sessions, clients, lock, gui_queue, log_message, broadcast_lists,
    handle_client, broadcast_message, SERVER_HOST, SERVER_PORT, MAX_CLIENTS,
    LOG_FILE, BROADCAST_INTERVAL, MAX_FILE_SIZE
)

class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("聊天服务器管理控制台")
        self.root.geometry("1200x800")
        self.root.configure(bg="#f0f0f0")
        self.server_running = False
        self.server_thread = None
        self.server_socket = None
        self.broadcast_thread = None
        global broadcast_running
        broadcast_running = False
        self.create_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.update_gui()

    def create_ui(self):
        control_frame = tk.Frame(self.root, bg="#e0e0e0", padx=10, pady=10)
        control_frame.pack(fill=tk.X)
        self.status_label = tk.Label(control_frame, text="服务器状态: 停止",
                                     bg="#e0e0e0", fg="#d32f2f", font=("Arial", 12, "bold"))
        self.status_label.pack(side=tk.LEFT, padx=10)
        self.start_btn = tk.Button(control_frame, text="启动服务器", command=self.start_server,
                                   bg="#4CAF50", fg="white", font=("Arial", 10), width=12)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = tk.Button(control_frame, text="停止服务器", command=self.stop_server,
                                  bg="#f44336", fg="white", font=("Arial", 10), width=12, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        clear_btn = tk.Button(control_frame, text="清空日志", command=self.clear_logs,
                              bg="#2196F3", fg="white", font=("Arial", 10), width=10)
        clear_btn.pack(side=tk.RIGHT, padx=5)
        refresh_btn = tk.Button(control_frame, text="刷新数据", command=self.refresh_data,
                                bg="#9C27B0", fg="white", font=("Arial", 10), width=10)
        refresh_btn.pack(side=tk.RIGHT, padx=5)
        main_frame = tk.Frame(self.root, bg="#f0f0f0")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        left_panel = tk.Frame(main_frame, bg="white", width=300, relief=tk.RAISED, borderwidth=1)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_panel.pack_propagate(False)
        session_frame = tk.LabelFrame(left_panel, text="活跃会话", bg="white", padx=5, pady=5)
        session_frame.pack(fill=tk.BOTH, padx=5, pady=5)
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
        user_frame = tk.LabelFrame(left_panel, text="在线用户", bg="white", padx=5, pady=5)
        user_frame.pack(fill=tk.BOTH, padx=5, pady=(0, 5))
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
        log_frame = tk.LabelFrame(main_frame, text="服务器日志", bg="white", padx=5, pady=5)
        log_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            bg="white",
            fg="#333",
            font=("Consolas", 10),
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text.tag_config("info", foreground="blue")
        self.log_text.tag_config("error", foreground="red")
        self.log_text.tag_config("warning", foreground="orange")
        self.log_text.tag_config("success", foreground="green")
        self.add_log("服务器管理控制台已启动", "info")
        self.add_log(f"服务器IP: {SERVER_HOST}, 端口: {SERVER_PORT}", "info")
        self.add_log("点击'启动服务器'按钮开始服务", "info")

    def start_server(self):
        if self.server_running:
            self.add_log("服务器已在运行中", "warning")
            return
        try:
            global sessions, clients, broadcast_running
            with lock:
                sessions.clear()
                clients.clear()
            self.server_thread = threading.Thread(target=self.run_server, daemon=True)
            self.server_running = True
            self.server_thread.start()
            broadcast_running = True
            self.broadcast_thread = threading.Thread(target=broadcast_lists, daemon=True)
            self.broadcast_thread.start()
            self.status_label.config(text="服务器状态: 运行中", fg="#388E3C")
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.add_log(f"服务器已启动在 {SERVER_HOST}:{SERVER_PORT}", "success")
            self.add_log(f"广播线程已启动，每{BROADCAST_INTERVAL}秒发送一次列表", "info")
        except Exception as e:
            self.add_log(f"启动服务器失败: {str(e)}", "error")
            self.server_running = False

    def run_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((SERVER_HOST, SERVER_PORT))
        self.server_socket.listen(MAX_CLIENTS)
        open(f"logs/{LOG_FILE}", "w", encoding='utf-8').close()
        try:
            while self.server_running:
                client_socket, client_address = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
        except Exception as e:
            if self.server_running:
                self.add_log(f"服务器错误: {str(e)}", "error")
        finally:
            self.server_socket.close()
            self.server_running = False

    def stop_server(self):
        if not self.server_running:
            self.add_log("服务器未运行", "warning")
            return
        global broadcast_running
        broadcast_running = False
        self.server_running = False
        try:
            self.server_socket.close()
        except:
            pass
        with lock:
            for client_socket in list(clients.keys()):
                try:
                    client_socket.close()
                except:
                    pass
            clients.clear()
            sessions.clear()
        self.status_label.config(text="服务器状态: 停止", fg="#d32f2f")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.add_log("服务器已停止", "info")
        self.session_tree.delete(*self.session_tree.get_children())
        self.user_tree.delete(*self.user_tree.get_children())

    def add_log(self, message, tag="info"):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] {message}\n"
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, formatted_msg, tag)
        self.log_text.config(state=tk.DISABLED)
        self.log_text.yview(tk.END)

    def update_sessions(self, session_list):
        self.session_tree.delete(*self.session_tree.get_children())
        with lock:
            for session_id in session_list:
                session = sessions.get(session_id)
                if session:
                    creator_socket = session['creator']
                    creator = clients.get(creator_socket, {}).get('username', '未知')
                    members = len(session['members'])
                    created = session['created'].strftime("%H:%M:%S")
                    self.session_tree.insert("", "end", text=session_id,
                                             values=(creator, members, created))

    def update_clients(self, client_list):
        self.user_tree.delete(*self.user_tree.get_children())
        for client in client_list:
            username = client.get('username', '未知')
            session = client.get('session', '无') or "无"
            address = f"{client.get('address', ('未知',))[0]}"
            login_time = client.get('login_time', datetime.datetime.now()).strftime("%H:%M:%S")
            self.user_tree.insert("", "end", text=username,
                                  values=(session, address, login_time))

    def update_gui(self):
        try:
            while not gui_queue.empty():
                item_type, data = gui_queue.get_nowait()
                if item_type == "log":
                    parts = data.split("|")
                    if len(parts) >= 3:
                        timestamp = parts[0].strip()
                        address = parts[1].strip()
                        direction_msg = parts[2].strip()
                        direction = direction_msg.split(":", 1)[0].strip()
                        message = direction_msg.split(":", 1)[1].strip() if ":" in direction_msg else direction_msg
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
        self.root.after(100, self.update_gui)

    def clear_logs(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.add_log("日志已清空", "info")

    def refresh_data(self):
        with lock:
            gui_queue.put(("sessions", list(sessions.keys())))
            gui_queue.put(("clients", list(clients.values())))
        self.add_log("数据已刷新", "info")

    def on_closing(self):
        if self.server_running:
            self.stop_server()
        self.root.destroy()

def start_server_gui():
    root = tk.Tk()
    app = ServerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    broadcast_running = False
    start_server_gui()
                                response_encoded = enc(response)
                                client_socket.send(response_encoded.encode('utf-8'))
                                continue
                            sender = parts[0].strip()
                            filename = parts[1].strip()
                            file_data = parts[2].strip()
                            file_size = (len(file_data) * 3) // 4
                            if file_size > MAX_FILE_SIZE:
                                response = "错误: 文件大小超过10MB限制"
                                response_encoded = enc(response)
                                client_socket.send(response_encoded.encode('utf-8'))
                            else:
                                safe_message = f"{file_type}:{sender}|{filename}|{file_data}"
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
                with lock:
                    if current_session in sessions:
                        broadcast_message(current_session, f"[{username}]: {command}", exclude=client_socket)
                        log_message(client_address, f"转发消息: {command}", "转发")
                    else:
                        response = "错误: 你不在任何会话中 😕"
                        response_encoded = enc(response)
                        client_socket.send(response_encoded.encode('utf-8'))
            else:
                response = "请先创建或加入一个会话 (CREATE, JOIN, LIST) 😊"
                response_encoded = enc(response)
                client_socket.send(response_encoded.encode('utf-8'))
    except ConnectionResetError:
        log_message(client_address, "客户端异常断开", "错误")
    except Exception as e:
        log_message(client_address, f"处理客户端错误: {str(e)}", "错误")
    finally:
        with lock:
            if client_socket in clients and clients[client_socket]['session']:
                session_id = clients[client_socket]['session']
                if session_id in sessions and client_socket in sessions[session_id]['members']:
                    del sessions[session_id]['members'][client_socket]
                    if not sessions[session_id]['members']:
                        del sessions[session_id]
                        log_message(client_address, f"会话 '{session_id}' 已关闭", "会话关闭")
                        gui_queue.put(("sessions", list(sessions.keys())))
            if client_socket in clients:
                del clients[client_socket]
                gui_queue.put(("clients", list(clients.values())))
        client_socket.close()
        log_message(client_address, "客户端连接关闭", "断开")

def broadcast_message(session_id, message, exclude=None):
    if session_id not in sessions:
        return
    try:
        message_encoded = enc(message)
    except Exception as e:
        log_message("SERVER", f"广播消息编码失败: {str(e)}", "错误")
        return
    for member_socket in sessions[session_id]['members']:
        if member_socket != exclude:
            try:
                member_socket.send(message_encoded.encode('utf-8'))
            except:
                pass

class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("聊天服务器管理控制台")
        self.root.geometry("1200x800")
        self.root.configure(bg="#f0f0f0")
        self.server_running = False
        self.server_thread = None
        self.server_socket = None
        self.broadcast_thread = None
        global broadcast_running
        broadcast_running = False
        self.create_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.update_gui()

    def create_ui(self):
        control_frame = tk.Frame(self.root, bg="#e0e0e0", padx=10, pady=10)
        control_frame.pack(fill=tk.X)
        self.status_label = tk.Label(control_frame, text="服务器状态: 停止",
                                     bg="#e0e0e0", fg="#d32f2f", font=("Arial", 12, "bold"))
        self.status_label.pack(side=tk.LEFT, padx=10)
        self.start_btn = tk.Button(control_frame, text="启动服务器", command=self.start_server,
                                   bg="#4CAF50", fg="white", font=("Arial", 10), width=12)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = tk.Button(control_frame, text="停止服务器", command=self.stop_server,
                                  bg="#f44336", fg="white", font=("Arial", 10), width=12, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        clear_btn = tk.Button(control_frame, text="清空日志", command=self.clear_logs,
                              bg="#2196F3", fg="white", font=("Arial", 10), width=10)
        clear_btn.pack(side=tk.RIGHT, padx=5)
        refresh_btn = tk.Button(control_frame, text="刷新数据", command=self.refresh_data,
                                bg="#9C27B0", fg="white", font=("Arial", 10), width=10)
        refresh_btn.pack(side=tk.RIGHT, padx=5)
        main_frame = tk.Frame(self.root, bg="#f0f0f0")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        left_panel = tk.Frame(main_frame, bg="white", width=300, relief=tk.RAISED, borderwidth=1)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_panel.pack_propagate(False)
        session_frame = tk.LabelFrame(left_panel, text="活跃会话", bg="white", padx=5, pady=5)
        session_frame.pack(fill=tk.BOTH, padx=5, pady=5)
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
        user_frame = tk.LabelFrame(left_panel, text="在线用户", bg="white", padx=5, pady=5)
        user_frame.pack(fill=tk.BOTH, padx=5, pady=(0, 5))
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
        log_frame = tk.LabelFrame(main_frame, text="服务器日志", bg="white", padx=5, pady=5)
        log_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            bg="white",
            fg="#333",
            font=("Consolas", 10),
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text.tag_config("info", foreground="blue")
        self.log_text.tag_config("error", foreground="red")
        self.log_text.tag_config("warning", foreground="orange")
        self.log_text.tag_config("success", foreground="green")
        self.add_log("服务器管理控制台已启动", "info")
        self.add_log(f"服务器IP: {SERVER_HOST}, 端口: {SERVER_PORT}", "info")
        self.add_log("点击'启动服务器'按钮开始服务", "info")

    def start_server(self):
        if self.server_running:
            self.add_log("服务器已在运行中", "warning")
            return
        try:
            global sessions, clients, broadcast_running
            with lock:
                sessions.clear()
                clients.clear()
            self.server_thread = threading.Thread(target=self.run_server, daemon=True)
            self.server_running = True
            self.server_thread.start()
            broadcast_running = True
            self.broadcast_thread = threading.Thread(target=broadcast_lists, daemon=True)
            self.broadcast_thread.start()
            self.status_label.config(text="服务器状态: 运行中", fg="#388E3C")
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.add_log(f"服务器已启动在 {SERVER_HOST}:{SERVER_PORT}", "success")
            self.add_log(f"广播线程已启动，每{BROADCAST_INTERVAL}秒发送一次列表", "info")
        except Exception as e:
            self.add_log(f"启动服务器失败: {str(e)}", "error")
            self.server_running = False

    def run_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((SERVER_HOST, SERVER_PORT))
        self.server_socket.listen(MAX_CLIENTS)
        open(f"logs/{LOG_FILE}", "w", encoding='utf-8').close()
        try:
            while self.server_running:
                client_socket, client_address = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
        except Exception as e:
            if self.server_running:
                self.add_log(f"服务器错误: {str(e)}", "error")
        finally:
            self.server_socket.close()
            self.server_running = False

    def stop_server(self):
        if not self.server_running:
            self.add_log("服务器未运行", "warning")
            return
        global broadcast_running
        broadcast_running = False
        self.server_running = False
        try:
            self.server_socket.close()
        except:
            pass
        with lock:
            for client_socket in list(clients.keys()):
                try:
                    client_socket.close()
                except:
                    pass
            clients.clear()
            sessions.clear()
        self.status_label.config(text="服务器状态: 停止", fg="#d32f2f")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.add_log("服务器已停止", "info")
        self.session_tree.delete(*self.session_tree.get_children())
        self.user_tree.delete(*self.user_tree.get_children())

    def add_log(self, message, tag="info"):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] {message}\n"
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, formatted_msg, tag)
        self.log_text.config(state=tk.DISABLED)
        self.log_text.yview(tk.END)

    def update_sessions(self, session_list):
        self.session_tree.delete(*self.session_tree.get_children())
        with lock:
            for session_id in session_list:
                session = sessions.get(session_id)
                if session:
                    creator_socket = session['creator']
                    creator = clients.get(creator_socket, {}).get('username', '未知')
                    members = len(session['members'])
                    created = session['created'].strftime("%H:%M:%S")
                    self.session_tree.insert("", "end", text=session_id,
                                             values=(creator, members, created))

    def update_clients(self, client_list):
        self.user_tree.delete(*self.user_tree.get_children())
        for client in client_list:
            username = client.get('username', '未知')
            session = client.get('session', '无') or "无"
            address = f"{client.get('address', ('未知',))[0]}"
            login_time = client.get('login_time', datetime.datetime.now()).strftime("%H:%M:%S")
            self.user_tree.insert("", "end", text=username,
                                  values=(session, address, login_time))

    def update_gui(self):
        try:
            while not gui_queue.empty():
                item_type, data = gui_queue.get_nowait()
                if item_type == "log":
                    parts = data.split("|")
                    if len(parts) >= 3:
                        timestamp = parts[0].strip()
                        address = parts[1].strip()
                        direction_msg = parts[2].strip()
                        direction = direction_msg.split(":", 1)[0].strip()
                        message = direction_msg.split(":", 1)[1].strip() if ":" in direction_msg else direction_msg
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
        self.root.after(100, self.update_gui)

    def clear_logs(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.add_log("日志已清空", "info")

    def refresh_data(self):
        with lock:
            gui_queue.put(("sessions", list(sessions.keys())))
            gui_queue.put(("clients", list(clients.values())))
        self.add_log("数据已刷新", "info")

    def on_closing(self):
        if self.server_running:
            self.stop_server()
        self.root.destroy()

def start_server_gui():
    root = tk.Tk()
    app = ServerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    broadcast_running = False
    start_server_gui()

