import zlib
import struct
import re

# Protocol Header
class Header:
    def __init__(self, Version, HeaderLen, PackageLen, ConnectionID, Login, Password, ControlSum):
        self.Version = Version
        self.HeaderLen = HeaderLen
        self.PackageLen = PackageLen
        self.ConnectionID = ConnectionID
        self.Login = Login.ljust(16)[:16]  # 16 bytes
        self.Password = Password.ljust(16)[:16]  # 16 bytes
        self.ControlSum = ControlSum
    
    def pack(self):
        print('def pack(self) in class Header happened')
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

    @staticmethod
    def calculate_checksum(DataToSend):
        return zlib.crc32(DataToSend) & 0xFFFF
    
    
    def pack(self):
        print('def pack(self) in class Package happened')
        # Упаковываем данные
        data_bytes = self.data.encode('utf-8')
        
        # Вычисляем PackageLen
        self.Header.PackageLen = self.Header.HeaderLen + len(data_bytes)
        
        # Вычисляем контрольную сумму данных
        self.Header.ControlSum = self.calculate_checksum(data_bytes)
        
        # Упаковываем заголовок
        header_bytes = self.Header.pack()
        
        # Формируем итоговый пакет
        return header_bytes + data_bytes

    @staticmethod
    def unpack(package_bytes):
        Header_format = '!BBH I 16s 16s H'
        Header_size = struct.calcsize(Header_format)
        Header_bytes = package_bytes[:Header_size]
        data_bytes = package_bytes[Header_size:]

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

        data = data_bytes.decode('utf-8')
        return Package(header, data)
    
    
    
    

def SecureDataMessage(data_message, Encrypt):
    return ' '.join([eval(Encrypt) for char in data_message])

def UnSecureDataMessage(data_message, Decipher):
    MessageList = re.split(' ', data_message)
    return ''.join([eval(Decipher) for code in MessageList])

