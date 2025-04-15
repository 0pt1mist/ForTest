import PSTP
import instructions
import application
import socket
import queue
import threading


def server():
    Encrypt, Decipher = instructions.read_config('MainConf.conf')
    LoginPasswordList = PSTP.read_login_config('MainConf.conf')

    Port = int(input('Port: '))
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('', Port)
    server_socket.bind(server_address)
    server_socket.listen(1)

    print(f"Server is listening on port {Port}...")

    packet_queue = queue.Queue()

    def handle_client(connection, client_address):
        try:
            print(f"Connection from {client_address}")

            # Аутентификация
            auth_data = connection.recv(4096)
            if auth_data:
                unpacked_auth_packet = PSTP.Package.unpack(auth_data)
                login = unpacked_auth_packet.Header.Login
                password = unpacked_auth_packet.Header.Password

                if LoginPasswordList.get(login) == password:
                    connection.sendall(b'AUTH_SUCCESS')
                    print("Authentication successful")
                    receiving = True
                else:
                    connection.sendall(b'AUTH_FAILURE')
                    print("Authentication failed")
                    receiving = False
                    connection.close()
                    return

            # Прием данных после успешной аутентификации
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
                print("Unpacked Header:", vars(unpacked_packet.Header))
                #print("Encrypted Data:", unpacked_packet.data)

                # Дешифруем данные
                unsecure_message = PSTP.UnSecureDataMessage(unpacked_packet.data, Decipher)
                print("Unsecure Data:", unsecure_message)

                # Проверка контрольной суммы
                calculated_checksum = unpacked_packet.calculate_checksum()
                print("Calculated Checksum:", calculated_checksum)
                print("Unpacked Checksum:", unpacked_packet.Header.ControlSum)
                if calculated_checksum == unpacked_packet.Header.ControlSum:
                    CheckValid = True
                    connection.sendall(b'GOOD')
                else:
                    CheckValid = False
                    connection.sendall(b'RESEND')
                print("Checksum Valid:", CheckValid)
                print("-----------------------------------------------------------------------------------")
            except Exception as e:
                print(f"Exception in process_packets: {e}")

    threading.Thread(target=process_packets, daemon=True).start()

    while True:
        connection, client_address = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(connection, client_address), daemon=True)
        client_thread.start()

def client():
    Encrypt, Decipher = instructions.read_config('MainConf.conf')

    IPadress = input('Address: ')
    Port = int(input('Port: '))
    server_address = (IPadress, Port)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(server_address)

    try:
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
            print("Authentication successful, proceeding to send data.")

        def handle_server_receive():
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
                        print("Message from server:", unsecure_message)
                except Exception as e:
                    print(f"Exception in handle_server_receive: {e}")
                    break

        def handle_client_send():
            while True:
                data_message = input("Message: ")
                if data_message == 'CloseCon':
                    print("Closing connection...")
                    client_socket.close()
                    break

                data_message = PSTP.SecureDataMessage(data_message, Encrypt)

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

                # Упаковываем пакет в массив байтов
                packed_packet = packet.pack()

                client_socket.sendall(packed_packet)



    except Exception as e:
        print(f"Exception in client: {e}")

    finally:
        client_socket.close()
        print("Connection closed")