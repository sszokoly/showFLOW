
import time
import select
import socket
import struct

BASE_TRY_NUM = 3
DEFAULT_COUNT_BYTE = 1024
MAX_TIME = 2

class TryData:

    def __init__(self, count_of_try: int = 3):
        self.count_of_success = 0
        self.all_try = []
        for num_of_try in range(count_of_try):
            self.all_try.append(0.0)
        self.addr = ''

    def add(self, num_of_try: int, value: float):
        self.all_try[num_of_try] = value
        self.count_of_success += 1

    def get_midle_sum(self):
        sum_all = 0
        for value in self.all_try:
            sum_all += value
        if not self.count_of_success:
            return 0.0
        return sum_all / self.count_of_success

def print_data(result: TryData):
    try:
        name = socket.gethostbyaddr(result.addr)[0]
    except socket.herror:
        name = 'Unknown server'
    finally:
        f_time = round(result.get_midle_sum() * 1000, 2)
        print(f'{result.addr:<15}    {name:<50}   {f_time} ms')

def make_socket_udp(num):
    proto_u = socket.getprotobyname('udp')
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto_u)
    udp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, num)
    return udp_socket

def make_socket_icmp(num, base_port):
    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                socket.getprotobyname("icmp"))
    icmp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL,
                           struct.pack('I', num))
    icmp_socket.settimeout(MAX_TIME)
    icmp_socket.bind(('', base_port + num))
    return icmp_socket

def get_route(addr: str, hop: int, base_port: int) -> list:
    res_data = []
    complete = False
    for ttl in range(1, hop+1):
        if complete:
            print('Complete')
            break
        cur = None
        result = TryData()
        print(f'{str(ttl)+")":<6}', end='')

        for num_of_try in range(BASE_TRY_NUM):
            with make_socket_udp(ttl) as udp_socket,\
                    make_socket_icmp(ttl, base_port) as icmp_socket:
                udp_socket.sendto(''.encode(), (addr, base_port + ttl))
                send_time = time.time()
                try:
                    in_select_socket = select.select([icmp_socket], [], [],
                                                     MAX_TIME)
                    if not in_select_socket[0]:
                        break
                    _, cur = icmp_socket.recvfrom(DEFAULT_COUNT_BYTE)
                    recv_time = time.time()
                    cur = cur[0]
                    result.addr = cur
                    result.add(num_of_try, recv_time-send_time)
                except socket.timeout:
                    continue

        if not result.count_of_success:
            print('* * *')

        if cur is not None:
            print_data(result)
            res_data.append(result)

        if cur == addr:
            print('Complete')
            break

        if ttl == hop:
            print("End of max hop")
            break
    return res_data

if __name__ == "__main__":
    get_route("8.8.8.8", 8, 2048)