import PSTP
import instructions
import socket
import threading

def handle_receive(client_socket, Decipher):
    """Функция для обработки получения сообщений от собеседника."""
    while True:
        try:
            server_response = client_socket.recv(4096)
            if not server_response:
                break
            if server_response == b'RESEND':
                print("Server requested to resend the packet due to checksum mismatch.")
            elif server_response == b'GOOD':
                print("Server acknowledged the packet.")
            else:
                unpacked_packet = PSTP.Package.unpack(server_response)
                unsecure_message = PSTP.UnSecureDataMessage(unpacked_packet.data, Decipher)
                print("Message from your friend:", unsecure_message)
        except Exception as e:
            print(f"Exception in handle_receive: {e}")
            break

def handle_send(client_socket, Encrypt, login, password):
    """Функция для обработки отправки сообщений пользователем."""
    while True:
        data_message = input("Message (type 'CloseCon' to close connection): ")
        if data_message == 'CloseCon':
            print("Closing connection...")
            client_socket.close()
            break

        # Шифруем данные
        data_message = PSTP.SecureDataMessage(data_message, Encrypt)

        # Формируем заголовок пакета
        header = PSTP.Header(
            Version=1,
            HeaderLen=24,
            PackageLen=len(data_message),
            ConnectionID=1,
            PackageType=1,
            SeqNumber=1,
            ConfirmNumber=0,
            Flags=0,
            Login=login,
            Password=password,
            ControlSum=0
        )
        packet = PSTP.Package(header, data_message)

        # Упаковываем и отправляем пакет
        packed_packet = packet.pack()
        client_socket.sendall(packed_packet)

def main():
    Encrypt, Decipher = instructions.read_config('MainConf.conf')

    IPadress = input('Enter the address of your friend: ')
    Port = int(input('Enter port: '))
    server_address = (IPadress, Port)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(server_address)

    login = input('Login = ').ljust(16)[:16]
    password = input('Password = ').ljust(16)[:16]

    auth_header = PSTP.Header(
        Version=1,
        HeaderLen=24,
        PackageLen=0,
        ConnectionID=1,
        Login=login,
        Password=password,
        ControlSum=0
    )
    auth_packet = PSTP.Package(auth_header, '')

    client_socket.sendall(auth_packet.pack())

    auth_response = client_socket.recv(4096)
    if auth_response == b'AUTH_FAILURE':
        print("Authentication failed, closing connection.")
        client_socket.close()
        return
    elif auth_response == b'AUTH_SUCCESS':
        print("Authentication successful, proceeding to send and receive data.")

    # Запуск потоков для отправки и получения сообщений
    threading.Thread(target=handle_receive, args=(client_socket, Decipher), daemon=True).start()
    threading.Thread(target=handle_send, args=(client_socket, Encrypt, login, password), daemon=True).start()

if __name__ == "__main__":
    main()
