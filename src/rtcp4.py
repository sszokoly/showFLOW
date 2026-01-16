"""
Avaya Sub-type 4 RTCP packet layout
+----------------+---------------+---------------+---------------+
|      Byte 1    |     Byte 2    |     Byte 3    |     Byte 4    |
+----------------+---------------+---------------+---------------+
| 0 1 2 3 4 5 6 7|8 9 0 1 2 3 4 5|6 7 8 9 0 1 2 3|4 5 6 7 8 9 0 1|
+----------------+---------------+---------------+---------------+
|Vers|P|Subytype |   PT=APP=204  |             Length            |
|                              SSRC                              |
|                           Name="-AV-"                          |
|               SSRC of the  Incoming RTP stream                 |
|                           Metric Mask                          |
|                       Received RTP Packets                     |
|                       Received RTP Octets                      |
|        Round-Trip Time         |     Jitter Buffer Delay       |
|Largest Seq Jump|Largest SeqFall|Maximum Jitter (1st&2nd bytes) |
|Maximum Jitter (3rd & 4th bytes)|Seq Jump Instances (1st 2 bytes|
|Seq Fall Instances (2nd 2 bytes)| IPv4 of remote (1st 2 bytes)  |
| IPv4 of remote (2nd 2 bytes)   |  IPv4 RTCP port of remote     |
|RTP payload type|   Frame Size  | Time to Live  | Received DSCP |
|Media Encryption|Silence Suppres|Incoming Stream RTP source port|
| Incoming Stream RTP dest port  | Null Terminate|Null Terminaten|
+----------------+---------------+---------------+---------------+
"""