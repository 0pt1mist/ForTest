import re


MAX_PACKET_SIZE = 16384

def read_config(file_path):
    print('config was readed')
    with open(file_path, 'r') as config:
        Encrypt = config.readline().strip()
        Decipher = config.readline().strip()
    return Encrypt, Decipher

def read_login_config(file_path):
    LoginPasswordList = {}
    with open(file_path, 'r') as config:
        lines = config.readlines()[2:]  # Skip the first two lines for Encrypt and Decipher
        for line in lines:
            if ':' in line:
                login, password = line.strip().split(':')
                LoginPasswordList[login.ljust(16)[:16]] = password.ljust(16)[:16]
    return LoginPasswordList

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
        if not code:
            continue
        try:
            MessageListUnSecure.append(eval(Decipher))
        except ValueError as e:
            print(f"Error decrypting message part '{code}': {e}")
            continue
    UnSecureMessage = ''.join(MessageListUnSecure)
    return UnSecureMessage