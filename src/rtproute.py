from scapy.all import *

# Define RTP header fields
rtp_packet = RTP(
    version=2,          # RTP version
    padding=0,         # Padding flag
    extension=0,       # Extension flag
    numsync=0,         # CSRC count
    marker=0,          # Marker bit
    payload_type=96,   # Payload type (dynamic type)
    sequence=1,        # Sequence number
    timestamp=123456,  # Timestamp
    sourcesync=12345,   # Synchronization source identifier
    sync=0
)

# Add payload (e.g., audio or video data)
payload = Raw(load=b'Your payload data here')
packet = rtp_packet / payload

# Send the RTP packet
send(IP(dst="192.168.168.254")/UDP(dport=2048)/packet)


#if __name__ == "__main__"   