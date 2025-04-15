import sys
import socket
import queue
import threading
import PSTP
import instructions
import connectionn as connectionn
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLineEdit, QPushButton, QLabel, QTextEdit, QHBoxLayout

servact = None
class Application(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("PSTP Client/Server Application")
        self.setGeometry(100, 100, 400, 400)

        self.init_ui()

    def init_ui(self):
        # Создаем элементы интерфейса
        self.layout = QVBoxLayout()

        # Поля для ввода
        self.ip_label = QLabel("IP Address:")
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Enter IP Address")

        self.port_label = QLabel("Port:")
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Enter Port")

        self.login_label = QLabel("Login:")
        self.login_input = QLineEdit()
        self.login_input.setPlaceholderText("Enter Login")

        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

        # Кнопки
        self.server_button = QPushButton("Start Server")
        self.client_button = QPushButton("Start Client")

        # Сообщения и статус
        self.status_label = QLabel("Status: Ready")

        # Поле для вывода сообщений
        self.messages_output = QTextEdit()
        self.messages_output.setReadOnly(True)  # Запрещаем редактировать текст

        # Поле для ввода сообщений
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your message here...")

        # Обработчики кнопок
        self.server_button.clicked.connect(self.start_server)
        self.client_button.clicked.connect(self.start_client)
        self.message_input.returnPressed.connect(self.send_message)

        # Добавляем элементы на экран
        self.layout.addWidget(self.ip_label)
        self.layout.addWidget(self.ip_input)
        self.layout.addWidget(self.port_label)
        self.layout.addWidget(self.port_input)
        self.layout.addWidget(self.login_label)
        self.layout.addWidget(self.login_input)
        self.layout.addWidget(self.password_label)
        self.layout.addWidget(self.password_input)

        self.layout.addWidget(self.server_button)
        self.layout.addWidget(self.client_button)

        self.layout.addWidget(self.status_label)

        self.layout.addWidget(self.messages_output)
        self.layout.addWidget(self.message_input)

        self.setLayout(self.layout)

    def update_messages(self, message):
        """Функция для обновления вывода сообщений."""
        self.messages_output.append(message)

    def start_server(self):
        ip = self.ip_input.text()
        port = self.port_input.text()
        if not ip or not port:
            self.status_label.setText("Status: IP and Port are required!")
            return

        self.status_label.setText(f"Status: Starting server on {ip}:{port}...")
        Port = int(port)

        def run_server():
            global servact, connection
            servact = True
            Encrypt, Decipher = instructions.read_config('MainConf.conf')
            LoginPasswordList = instructions.read_login_config('MainConf.conf')

            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_address = ('', Port)
            server_socket.bind(server_address)
            server_socket.listen(1)

            print(f"Server is listening on port {Port}...")

            packet_queue = queue.Queue()

            def handle_client(connection, client_address): 
                try:
                    self.update_messages(f"Connection from {client_address}")
                    auth_data = connection.recv(4096)
                    receiving = False
                    if auth_data:
                        unpacked_auth_packet = PSTP.Package.unpack(auth_data)
                        login = unpacked_auth_packet.Header.Login
                        password = unpacked_auth_packet.Header.Password

                        if LoginPasswordList.get(login) == password:
                            connection.sendall(b'AUTH_SUCCESS')
                            self.update_messages("Authentication successful")
                            receiving = True
                        else:
                            connection.sendall(b'AUTH_FAILURE')
                            self.update_messages("Authentication failed")
                            receiving = False
                            connection.close()
                            return

                    while receiving:
                        
                        data = connection.recv(4096)
                        if data:
                            packet_queue.put((data, connection))

                except Exception as e:
                    print(f"Exception in handle_client: {e}")

            def process_packets():
                while True:
                    try:
                        data, connection = packet_queue.get()
                        unpacked_packet = PSTP.Package.unpack(data)
                        #self.update_messages(f"Unpacked Header: {vars(unpacked_packet.Header)}")

                        unsecure_message = PSTP.UnSecureDataMessage(unpacked_packet.data, Decipher)
                        self.update_messages(f"Unsecure Data: {unsecure_message}")

                        calculated_checksum = unpacked_packet.calculate_checksum(data)
                        if calculated_checksum == unpacked_packet.Header.ControlSum:
                            connection.sendall(b'GOOD')
                        else:
                            connection.sendall(b'R ESEND')
                        


                        ######
                    except Exception as e:
                        print(f"Exception in process_packets: {e}")

            threading.Thread(target=process_packets, daemon=True).start()

            while True:
                connection, client_address = server_socket.accept()
                client_thread = threading.Thread(target=handle_client, args=(connection, client_address), daemon=True)
                client_thread.start()

        threading.Thread(target=run_server, daemon=True).start()

    def start_client(self):
        global login, password
        ip = self.ip_input.text()
        port = self.port_input.text()
        login = self.login_input.text()
        password = self.password_input.text()

        if not ip or not port or not login or not password:
            self.status_label.setText("Status: All fields are required!")
            return

        self.status_label.setText(f"Status: Connecting to {ip}:{port}...")

        def run_client():
            global client_socket
            Encrypt, Decipher = instructions.read_config('MainConf.conf')

            server_address = (ip, int(port))
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect(server_address)

            auth_header = PSTP.Header(
                Version=1,
                HeaderLen=24,
                PackageLen=0,
                ConnectionID=1,
                Login=login.ljust(16)[:16],
                Password=password.ljust(16)[:16],
                ControlSum=0
            )
            auth_packet = PSTP.Package(auth_header, '')

            client_socket.sendall(auth_packet.pack())
            auth_response = client_socket.recv(4096)

            if auth_response == b'AUTH_FAILURE':
                self.status_label.setText("Status: Authentication failed!")
                client_socket.close()
                return
            elif auth_response == b'AUTH_SUCCESS':
                self.status_label.setText("Status: Authentication successful!")

            threading.Thread(target=connectionn.handle_receive, args=(client_socket, Decipher), daemon=True).start()
            threading.Thread(target=connectionn.handle_send, args=(client_socket, Encrypt, login, password), daemon=True).start()

        threading.Thread(target=run_client, daemon=True).start()

    def send_message(self):
        Encrypt, Decipher = instructions.read_config('MainConf.conf')
        """Функция отправки сообщений, вызываемая при нажатии Enter."""
        message = self.message_input.text()
        data_message = None
        if message.strip() != '':
            self.update_messages(f"You: {message}")
            self.message_input.clear()  # Очистить поле ввода

            data_message = instructions.SecureDataMessage(message, Encrypt)
            if servact:
                header = PSTP.Header(
                    Version=4,
                    HeaderLen=24,
                    PackageLen=0,  # Временно 0
                    ConnectionID=1,
                    Login='serv',
                    Password='serv',
                    ControlSum=0  # Временно 0
                )
            else:
                header = PSTP.Header(
                        Version=4,
                        HeaderLen=24,
                        PackageLen=0,  # Временно 0
                        ConnectionID=1,
                        Login=login,
                        Password=password,
                        ControlSum=0  # Временно 0
                    )
            
            packet = PSTP.Package(header, data_message)
            packed_packet = packet.pack()
            if len(packed_packet) > 65535:
                    print(f"Warning: packet size {len(packed_packet)} exceeds 65535 bytes limit, packet will not be sent.")
            if servact:
                connection.sendall(packed_packet)
            else:
                client_socket.sendall(packed_packet)



def main():
    app = QApplication(sys.argv)
    window = Application()
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
