import os
import uuid
from socket import *
import json
import hashlib
import argparse
import struct
import time
from threading import Thread
from tqdm import tqdm

MAX_PACKET_SIZE = 20480
SERVER_PORT = 1379
MAX_RETRIES = 3  # Maximum number of retransmissions
RETRY_INTERVAL = 20
SERVER_IP: str
token = ''  # test

# Const Value
OP_SAVE, OP_DELETE, OP_GET, OP_UPLOAD, OP_DOWNLOAD, OP_BYE, OP_LOGIN, OP_ERROR = \
    'SAVE', 'DELETE', 'GET', 'UPLOAD', 'DOWNLOAD', 'BYE', 'LOGIN', "ERROR"
TYPE_FILE, TYPE_DATA, TYPE_AUTH, DIR_EARTH = 'FILE', 'DATA', 'AUTH', 'EARTH'
FIELD_OPERATION, FIELD_DIRECTION, FIELD_TYPE, FIELD_USERNAME, FIELD_PASSWORD, FIELD_TOKEN = \
    'operation', 'direction', 'type', 'username', 'password', 'token'
FIELD_KEY, FIELD_SIZE, FIELD_TOTAL_BLOCK, FIELD_MD5, FIELD_BLOCK_SIZE = \
    'key', 'size', 'total_block', 'md5', 'block_size'
FIELD_STATUS, FIELD_STATUS_MSG, FIELD_BLOCK_INDEX = 'status', 'status_msg', 'block_index'
DIR_REQUEST, DIR_RESPONSE = 'REQUEST', 'RESPONSE'

# global
file_upload_successfully = False


# Parsing the command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="Run client.py to login and obtain a token.")
    parser.add_argument('--server_ip', type=str, help='Server IP address')
    parser.add_argument('--id', type=str, required=True, help='Student ID')
    parser.add_argument('--file_path', type=str, required=True, help='Address of file')
    return parser.parse_args()


# Creating packets
def make_packet(types, operations, json_data, bin_data=None, direction=DIR_REQUEST):
    global token
    if token != '':
        json_data[FIELD_TOKEN] = token

    json_data[FIELD_DIRECTION] = direction
    json_data[FIELD_TYPE] = types
    json_data[FIELD_OPERATION] = operations
    j = json.dumps(dict(json_data), ensure_ascii=False)
    j_len = len(j)
    if bin_data is None:
        return struct.pack('!II', j_len, 0) + j.encode()
    else:
        return struct.pack('!II', j_len, len(bin_data)) + j.encode() + bin_data


# Fetching packets
def get_tcp_packet(conn):
    """
    Receive a complete TCP "packet" from a TCP stream and get the json data and binary data.
    :param conn: the TCP connection
    :return:
        json_data
        bin_data
    """
    bin_data = b''
    while len(bin_data) < 8:
        data_rec = conn.recv(8)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    data = bin_data[:8]
    bin_data = bin_data[8:]
    j_len, b_len = struct.unpack('!II', data)
    while len(bin_data) < j_len:
        data_rec = conn.recv(j_len)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    j_bin = bin_data[:j_len]

    try:
        json_data = json.loads(j_bin.decode())
    except Exception as ex:
        return None, None

    bin_data = bin_data[j_len:]
    while len(bin_data) < b_len:
        data_rec = conn.recv(b_len)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    return json_data, bin_data


# Exception handling
def handle_error(e, attempt, max_retries):
    print(f"Connection attempt {attempt} failed: {e}. line: {e.__traceback__.tb_lineno}")
    if attempt >= max_retries:
        print("Max retries reached. Please check the issue and try again later.")
        raise Exception("Login failed after several attempts")
    print(f"Retrying in {RETRY_INTERVAL} seconds...")
    time.sleep(RETRY_INTERVAL)


# login
def login(username):
    global token
    retries = 0
    # token = None
    while retries < MAX_RETRIES:
        try:
            with create_connection((SERVER_IP, SERVER_PORT)) as sock:
                password = hashlib.md5(username.encode()).hexdigest()
                print(f"PASSWORD: {password}")
                # Construct the JSON message for the login request
                login_data = {FIELD_USERNAME: username, FIELD_PASSWORD: password}
                login_packet = make_packet(TYPE_AUTH, OP_LOGIN, login_data)
                sock.sendall(login_packet)
                response_json, _ = get_tcp_packet(sock)
                # Check the status code of the response
                if response_json.get(FIELD_STATUS) == 200:
                    token = response_json.get(FIELD_TOKEN)
                    print(f"Login successful. Token: {token}")
                    break
                else:
                    raise Exception(f"Login failed: {response_json.get(FIELD_STATUS_MSG)}")
        except Exception as e:
            handle_error(e, retries + 1, MAX_RETRIES)
            retries += 1
    return token


def open_bin_file(path):
    """
    Binary reading files
:param path: The file address
:return: file size, md5 value of the file, binary file
    """
    with open(path, 'rb') as f:
        bin_f = f.read()
        size = len(bin_f)
        f_md5 = hashlib.md5(bin_f).hexdigest()
        return size, f_md5, bin_f


# Sending a block
def block_thread(client_socket, block_packet, block_idx, file_md5):
    global file_upload_successfully
    client_socket.settimeout(RETRY_INTERVAL)
    for retries in range(MAX_RETRIES):
        # Sending block packets
        client_socket.sendall(block_packet)

        block_upload_successfully = False
        while not block_upload_successfully:
            try:
                # Accepting a response
                response_json, _ = get_tcp_packet(client_socket)

                # Check the status code of the response
                if response_json[FIELD_STATUS] == 200:
                    if response_json[FIELD_BLOCK_INDEX] == block_idx:
                        if FIELD_MD5 in response_json:
                            if response_json[FIELD_MD5] == file_md5:
                                file_upload_successfully = True
                            else:
                                file_upload_successfully = False
                        block_upload_successfully = True
                else:
                    file_upload_successfully = False
                    print(f"Upload block {block_idx} failed: "
                          f"{response_json[FIELD_STATUS]} {response_json[FIELD_STATUS_MSG]}, "
                          f"retries: {retries + 1}")
            except Exception as e:
                print(f"error info: {e}, block {block_idx}. retries: {retries + 1}")
                time.sleep(0.1)
                break

        else:
            break


# A class that implements the GBN
class SendBlockThQueue:
    def __init__(self, block_th_list: list, n: int):
        self.block_th_list = block_th_list
        self.n = n
        self.pointer = 0

        # start block_thread in window
        if len(self.block_th_list) < n:
            for block_th in self.block_th_list:
                block_th.start()
        else:
            for idx in range(n):
                self.block_th_list[idx].start()
                time.sleep(0.01)

    def move_window(self):
        if not self.block_th_list[self.pointer].is_alive():
            self.pointer += 1
            if (self.pointer + self.n - 1) < len(self.block_th_list):
                self.block_th_list[self.pointer + self.n - 1].start()
            if self.pointer >= len(self.block_th_list):
                self.pointer -= 1
                return True, False
            return True, True
        return False, True

    def __len__(self):
        return len(self.block_th_list)


# Chunk upload
def upload_request(file_key, json_data, bin_file, file_md5, client_socket):
    """
    :param file_key:
    :param json_data: A json file containing the upload plan
    :param bin_file: The binary file to upload
    :param file_md5: The MD5 value of the file
    :param client_socket:
    :return:
    """
    global file_upload_successfully

    total_block = json_data[FIELD_TOTAL_BLOCK]
    block_size = json_data[FIELD_BLOCK_SIZE]

    retries = 0
    file_upload_successfully = False
    while retries < MAX_RETRIES and not file_upload_successfully:
        th_list = []  # Multithreaded upload process list
        # Chunk upload
        for block_index in range(total_block):
            # Construct block files (except the last one)
            block_index_dic = {FIELD_KEY: file_key, FIELD_BLOCK_INDEX: block_index}
            if block_index == total_block-1:
                bin_data = bin_file[(total_block - 1) * block_size:]
            else:
                bin_data = bin_file[block_index * block_size: (block_index + 1) * block_size]
            block_packet = make_packet(TYPE_FILE, OP_UPLOAD, block_index_dic, bin_data)

            # Multiple threads upload simultaneously
            th = Thread(target=block_thread, args=(client_socket, block_packet, block_index, file_md5))
            th_list.append(th)

        gbn_th_queue = SendBlockThQueue(th_list, 10)

        # Check upload progress
        with tqdm(total=len(gbn_th_queue)) as pbar:
            pbar.set_description('Progress of successful file upload: ')
            have_alive = True
            while have_alive:
                pointer_th_not_alive, have_alive = gbn_th_queue.move_window()
                if pointer_th_not_alive:
                    pbar.update(1)
                time.sleep(0.1)

        retries += 1

    if file_upload_successfully:
        print('Upload Completed')
    else:
        raise Exception('Upload Failed')


# Application upload
def save_request(file_size, bin_file, file_md5, file_key=None):
    """
    Block concurrent upload
    """
    # Create a socket
    client_socket = socket(AF_INET, SOCK_STREAM)
    # Connecting to the server
    client_socket.connect((SERVER_IP, SERVER_PORT))

    # Easter egg
    if file_key == "The three body problem":
        easter_egg_packet = make_packet(DIR_EARTH, 'EARTH', {}, direction=DIR_EARTH)
        client_socket.sendall(easter_egg_packet)

        json_data, _ = get_tcp_packet(client_socket)
        if json_data[FIELD_STATUS] == 333:
            print(f"\nSERVER RESPONSE: {json_data[FIELD_STATUS_MSG]}\n")
        else:
            print('Do you really believe that the Trisolarans exist? That\'s ridiculous')

        time.sleep(1)

    # Construct a request to save the file
    save_data = {FIELD_SIZE: file_size, FIELD_KEY: file_key}
    save_packet = make_packet(TYPE_FILE, OP_SAVE, save_data)

    # Send a request to save the file
    client_socket.sendall(save_packet)
    # Receives the response from the server
    json_data, _ = get_tcp_packet(client_socket)

    try:
        # Check the status code of the response
        if json_data[FIELD_STATUS] == 200:
            print("Start uploading file.")
            upload_request(json_data=json_data, file_key=file_key, bin_file=bin_file,
                           file_md5=file_md5, client_socket=client_socket)
        else:
            raise Exception(f"Save request failed: {json_data.get(FIELD_STATUS_MSG)}")
    except Exception as e:
        print(f"Upload Error: {e}, line: {e.__traceback__.tb_lineno}")

    client_socket.close()


def main():
    global SERVER_IP, token     # test
    args = parse_arguments()

    # Sets the IP address of the server
    SERVER_IP = args.server_ip
    username = args.id
    file_path = args.file_path

    token = login(username)
    if token:
        file_size, file_md5, bin_file = open_bin_file(file_path)
        file_name = os.path.basename(file_path)
        file_key = str(uuid.uuid4()) + os.path.splitext(file_name)[-1]
        save_request(file_key=file_key, file_size=file_size, file_md5=file_md5, bin_file=bin_file)


if __name__ == "__main__":
    main()
