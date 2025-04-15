import zlib
import struct
import base64
import re
# Python Simple Transmission Protocol
Version = 'Rebuild'


# Protocol Header
class Header:
    def __init__(self, Version, HeaderLen, PackageLen, IP, ConnectionID, Login, Password, ControlSum):
        self.Version = Version
        self.HeaderLen = HeaderLen
        self.PackageLen = PackageLen
        self.IP = IP
        self.ConnectionID = ConnectionID
        self.Login = Login.ljust(16)[:16] # 16 bytes
        self.Password = Password.ljust(16)[:16] # 16 bytes
        self.ControlSum = ControlSum

    def pack(self):
        print(self.ControlSum)
        return struct.pack(
            '!BBH I 16s 16s H',
            self.Version,
            self.HeaderLen,
            self.PackageLen,
            self.ConnectionID,
            self.Login.encode('utf-8'),
            self.Password.encode('utf-8'),
            self.ControlSum
        )

class Package:
    def __init__(self, Header, data):
        self.Header = Header
        self.data = data

    def calculate_checksum(DataToSend):
        checksum = zlib.crc32(DataToSend) & 0xFFFF
        return checksum
    
    @staticmethod
    def unpack(package_bytes):
        # Распаковываем заголовок
        Header_format = '!BBH I 16s 16s H'
        Header_size = struct.calcsize(Header_format)
        Header_bytes = package_bytes[:Header_size]
        data_bytes = package_bytes[Header_size:]

        # Распаковываем заголовок
        unpacked_header = struct.unpack(Header_format, Header_bytes)
        header = Header(
            Version=unpacked_header[0],
            HeaderLen=unpacked_header[1],
            PackageLen=unpacked_header[2],
            ConnectionID=unpacked_header[3],
            Login=unpacked_header[4].decode('utf-8').strip(),
            Password=unpacked_header[5].decode('utf-8').strip(),
            ControlSum=unpacked_header[6]
        )

        # Данные находятся после заголовка
        data = data_bytes.decode('utf-8')
        return Package(header, data)

def SecureDataMessage(data_message, Encrypt):
    MessageList = []
    for i, char in enumerate(data_message):
        MessageList.append(eval(Encrypt))
    SecMessage = ' '.join(MessageList)
    return SecMessage

def UnSecureDataMessage(data_message, Decipher):
    MessageList = re.split(' ', data_message)
    MessageListUnSecure = []
    for code in MessageList:
        MessageListUnSecure.append(eval(Decipher))
    UnSecureMessage = ''.join(MessageListUnSecure)
    return UnSecureMessage

def read_login_config(file_path):
    LoginPasswordList = {}
    with open(file_path, 'r') as config:
        lines = config.readlines()[2:]  # Skip the first two lines for Encrypt and Decipher
        for line in lines:
            if ':' in line:
                login, password = line.strip().split(':')
                LoginPasswordList[login.ljust(16)[:16]] = password.ljust(16)[:16]
    return LoginPasswordList

LoginPasswordList = read_login_config('MainConf.conf')