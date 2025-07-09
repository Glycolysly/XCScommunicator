import socket
import threading
import sys

SERVER_IP = '218.12.120.170'  # 服务器IP
SERVER_PORT = 62599  # 服务器端口


class ChatClient:
    def __init__(self):
        self.client_socket = None
        self.username = None
        self.current_session = None
        self.running = True

    def connect(self):
        """连接到服务器"""
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((SERVER_IP, SERVER_PORT))

            # 设置用户名
            self.username = input("请输入用户名: ")
            self.client_socket.send(self.username.encode('utf-8'))

            # 接收欢迎消息
            welcome = self.client_socket.recv(1024).decode('utf-8')
            print(welcome)

            return True
        except Exception as e:
            print(f"连接失败: {str(e)}")
            return False

    def receive_messages(self):
        """接收服务器消息"""
        while self.running:
            try:
                data = self.client_socket.recv(1024).decode('utf-8')
                if not data:
                    print("[!] 与服务器的连接已断开")
                    self.running = False
                    break

                print(f"\n{data}\n> ", end="", flush=True)

            except:
                self.running = False
                break

    def send_command(self, command):
        """发送命令到服务器"""
        try:
            self.client_socket.send(command.encode('utf-8'))
        except:
            print("[!] 发送命令失败")
            self.running = False

    def start(self):
        """启动客户端"""
        if not self.connect():
            return

        # 启动接收线程
        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.daemon = True
        receive_thread.start()

        # 主循环处理用户输入
        while self.running:
            try:
                user_input = input("> ").strip()
                if not user_input:
                    continue

                if user_input.lower() == '/exit':
                    if self.current_session:
                        self.send_command("LEAVE")
                    self.running = False
                    break

                elif user_input.lower() == '/list':
                    self.send_command("LIST")

                elif user_input.lower().startswith('/create '):
                    session_id = user_input.split(" ", 1)[1].strip()
                    self.send_command(f"CREATE {session_id}")
                    self.current_session = session_id

                elif user_input.lower().startswith('/join '):
                    session_id = user_input.split(" ", 1)[1].strip()
                    self.send_command(f"JOIN {session_id}")
                    self.current_session = session_id

                elif user_input.lower() == '/leave':
                    self.send_command("LEAVE")
                    self.current_session = None

                else:
                    # 普通消息
                    self.send_command(user_input)

            except KeyboardInterrupt:
                print("\n正在退出...")
                self.running = False
                break

        # 清理
        try:
            self.client_socket.close()
        except:
            pass
        print("客户端已关闭")


if __name__ == "__main__":
    print("=== 会话聊天系统 ===")
    print("命令说明:")
    print("  /create [会话ID] - 创建新会话")
    print("  /join [会话ID]   - 加入现有会话")
    print("  /list           - 查看所有会话")
    print("  /leave          - 离开当前会话")
    print("  /exit           - 退出程序")
    print("在会话中直接输入消息即可发送给所有会话成员\n")

    client = ChatClient()
    client.start()