import socket
import struct
import zlib
import threading
from PSTP import Header, Package

MAX_PACKET_SIZE = 16384



def send(Header, DataToSend):
    from application import IP
    ControlSum = Package.calculate_checksum(DataToSend)
    Package = str((Header, DataToSend).join)
    print(Package)
    pass

def receive():
    pass

def read_config(file_path):
    with open(file_path, 'r') as config:
        Encrypt = config.readline().strip()
        Decipher = config.readline().strip()
    return Encrypt, Decipher