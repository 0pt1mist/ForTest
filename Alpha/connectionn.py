import threading
import PSTP
import instructions

def handle_receive(client_socket, Decipher):
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
            #break

def handle_send(client_socket, Encrypt, login, password):
    while True:
        data_message = input("Message (type 'CloseCon' to close connection): ")
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
            Login=login,
            Password=password,
            ControlSum=0
        )
        packet = PSTP.Package(header, data_message)
        packed_packet = packet.pack()
        client_socket.sendall(packed_packet)
