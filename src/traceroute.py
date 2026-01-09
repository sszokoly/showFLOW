
import time
import select
import socket
import struct
import fcntl
import array

try:
    import netifaces
    get_interface_names = netifaces.interfaces
except ModuleNotFoundError:
    def get_interface_names():
        max_interfaces = 128
        bytes_size = max_interfaces * 40  # Increased size for 64-bit
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        names = array.array('B', b'\0' * bytes_size)

        outbytes = struct.unpack('iL', fcntl.ioctl(
            s.fileno(),
            0x8912,  # SIOCGIFCONF
            struct.pack('iL', bytes_size, names.buffer_info()[0])
        ))[0]

        namestr = names.tobytes()
        interfaces = []

        # Parse the structure more carefully
        i = 0
        while i < outbytes:
            name = namestr[i:i+16].split(b'\0', 1)[0].decode('utf-8')
            if name:
                interfaces.append(name)
            i += 40  # Size of ifreq structure on 64-bit systems

        return [x for x in set(interfaces) if x]


DEFAULT_COUNT_BYTE = 1024

class TryData:

    def __init__(self, count_of_try: int = 3):
        self.count_of_success = 0
        self.all_try = []
        for num_of_try in range(count_of_try):
            self.all_try.append(0.0)
        self.host = ''

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

def print_data(result: TryData, dont_resolve: bool = False):
    if not dont_resolve:
        try:
            name = socket.gethostbyaddr(result.host)[0]
        except socket.herror:
            name = 'Unknown server'
    else:
        name = result.host

    f_time = round(result.get_midle_sum() * 1000, 2)
    print(f'{result.host:<15}    {name:<50}   {f_time} ms')

def make_socket_udp(ttl, device=None, src_addr='0.0.0.0', sport=0):
    devices = [x for x in get_interface_names() if x != 'lo']
    if not devices:
        raise OSError("No network devices found (excluding loopback)")
    else:
        device = devices[0]
    proto_u = socket.getprotobyname('udp')
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto_u)
    udp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

    # Bind to specific interface if provided
    if device:
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, 
                              device.encode())

    udp_socket.bind((src_addr, sport))
    return udp_socket

def make_socket_icmp(ttl, port, device=None, src_addr='0.0.0.0', sport=0, max_wait=2):
    proto_i = socket.getprotobyname('icmp')
    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto_i)
    icmp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    icmp_socket.settimeout(max_wait)
    
    # Bind to specific interface if provided
    if device:
        icmp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, 
                              device.encode())
    
    icmp_socket.bind((src_addr, sport if sport else port + ttl))
    return icmp_socket

def get_route(host: str,
        max_ttl: int = 30,
        port: int = 33434,
        dont_resolve: bool = False,
        first_ttl: int = 1,
        device = None,
        src_addr: str = '0.0.0.0',
        sport: int = 0,
        nqueries: int = 3,
        udp: bool = False,
        max_wait: int = 2,
        packetlen: int = 40
    ) -> list:
    res_data = []
    complete = False
    try:
        for ttl in range(first_ttl, max_ttl+1):
            if complete:
                print('Complete')
                break
            cur = None
            result = TryData()
            print(f' {str(ttl):<6}', end='')

            for num_of_try in range(nqueries):
                with make_socket_udp(ttl, device=device, src_addr=src_addr, sport=sport) as udp_socket,\
                        make_socket_icmp(ttl, port, device=device, src_addr=src_addr, sport=sport) as icmp_socket:
                    payload = 'a' * packetlen
                    udp_socket.sendto(payload.encode(), (host, port + ttl))
                    send_time = time.time()
                    try:
                        in_select_socket = select.select([icmp_socket], [], [],
                                                        max_wait)
                        if not in_select_socket[0]:
                            break
                        _, cur = icmp_socket.recvfrom(DEFAULT_COUNT_BYTE)
                        recv_time = time.time()
                        cur = cur[0]
                        result.host = cur
                        result.add(num_of_try, recv_time-send_time)
                    except socket.timeout:
                        continue

            if not result.count_of_success:
                print('* * *')

            if cur is not None:
                print_data(result, dont_resolve)
                res_data.append(result)

            if cur == host:
                print('Complete')
                break

            if ttl == max_ttl:
                print("End of max max_ttl")
                break
        return res_data
    except Exception as e:
        print(f'{repr(e)}')
        return 1

if __name__ == "__main__":
    import argparse
    import sys
    sys.argv.extend(['--sport', '2048', '-q', '1', '-m', '1', '8.8.8.8'])
    parser = argparse.ArgumentParser(description='UDP traceroute')
    parser.add_argument('-f', '--first', dest='first_ttl', type=int,
                        default=1, 
                        help='Start from the first_ttl max_ttl (instead from 1)')
    parser.add_argument('-I', '--icmp', dest='icmp', action='store_true',
                        default=True,
                        help='Use ICMP ECHO for tracerouting')
    parser.add_argument('-i', '--interface', dest='device',
                        default=None,
                        help='Specify a network interface to operate with')
    parser.add_argument('-m', '--max-max_ttls', dest='max_ttl', type=int,
                        default=30,
                        help='Set the max number of max_ttls (max TTL to bereached). Default 30')
    parser.add_argument('-n', dest='dont_resolve', action='store_true',
                        default=False,
                        help='Do not resolve IP hostesses to their domain names')
    parser.add_argument('-p', '--port', dest='port', type=int,
                        default=33434,
                        help='Set the destination port to use, Default 33434')
    parser.add_argument('-w', '--wait', dest='max_wait', type=int,
                        default=2,
                        help='Wait for a probe no more than this seconds. Default 2')
    parser.add_argument('-q', '--queries', dest='nqueries', type=int,
                        default=3,
                        help='Set the number of probes per each max_ttl. Default 3')
    parser.add_argument('-s', '--source', dest='src_addr',
                        default='0.0.0.0',
                        help='Use source src_addr for outgoing packets')
    parser.add_argument('--sport', dest='sport', type=int,
                        default=2048,
                        help='Use source port num for outgoing packets, Default 2048')
    parser.add_argument('-U', '--udp', dest='udp', action='store_true',
                        default=False,
                        help='Use UDP to particular port for tracerouting')
    parser.add_argument('--packetlen', dest='packetlen', type=int,
                        default=40,
                        help='The full packet length')
    parser.add_argument('host', help='Host hostess')
    args = parser.parse_args()
    get_route(args.host,
        args.max_ttl,
        args.port,
        dont_resolve=args.dont_resolve,
        first_ttl=args.first_ttl,
        device=args.device,
        src_addr=args.src_addr,
        sport=args.sport,
        nqueries=args.nqueries,
        udp=args.udp,
        max_wait=args.max_wait,
        packetlen=args.packetlen
    )
