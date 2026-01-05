

"""
[root@SD36SBCE ~]# sbceinfo gethwtype
HwType 310
310

[root@SD36SBCE ~]# showflow 310 dynamic 9
0 [10.10.48.58:2050 -> 10.10.48.192:35046] DecEna DEC srtp MKlen 10 SltLen e TlkSpt 0 SSRC[0] 5becd55d{0} SSRC[1] 0{0} SSRC[2] 0{0} ROC[0] 0 ROC[1] 0 ROC[2] 0 sq[0] 12d sq[1] 0 sq[2] 0 EncEna ENC srtp MKlen 10 SltLen e TlkSpt 0 SSRC[0] 5becd55d{0} SSRC[1] 0{0} SSRC[2] 0{0} ROC[0] 0 ROC[1] 0 ROC[2] 0 sq[0] 12d sq[1] 0 sq[2] 0 OUT 3 RELAY 10.10.32.60:35056 -> 162.248.168.234:47294 mac 0:c:29:30:7d:9f -> 20:23:51:b2:7e:50 rtcp_echo 0 in VLAN 0 out VLAN 0 Enc 12d Dec 12d Snt 0 Drp 0 Rx 12d Rly 12d ECH 0
0 [10.10.48.58:2051 -> 10.10.48.192:35047] OUT 3 RELAY 10.10.32.60:35057 -> 162.248.168.234:47295 mac 0:c:29:30:7d:9f -> 0:0:0:0:0:0 rtcp_echo 0 in VLAN 0 out VLAN 0 Enc 0 Dec 0 Snt 0 Drp 0 Rx a Rly a ECH 0
3 [162.248.168.234:47294 -> 10.10.32.60:35056] DecEna DEC srtp MKlen 10 SltLen e TlkSpt 0 SSRC[0] e8e97144{0} SSRC[1] 0{0} SSRC[2] 0{0} ROC[0] 0 ROC[1] 0 ROC[2] 0 sq[0] 7c40 sq[1] 0 sq[2] 0 EncEna ENC srtp MKlen 10 SltLen e TlkSpt 0 SSRC[0] e8e97144{0} SSRC[1] 0{0} SSRC[2] 0{0} ROC[0] 0 ROC[1] 0 ROC[2] 0 sq[0] 7c40 sq[1] 0 sq[2] 0 OUT 0 RELAY 10.10.48.192:35046 -> 10.10.48.58:2050 mac 0:c:29:30:7d:a9 -> 0:1b:4f:3f:73:e0 rtcp_echo 0 in VLAN 0 out VLAN 0 Enc 12c Dec 12c Snt 0 Drp 0 Rx 12c Rly 12c ECH 0
3 [162.248.168.234:47295 -> 10.10.32.60:35057] OUT 0 RELAY 10.10.48.192:35047 -> 10.10.48.58:2051 mac 0:c:29:30:7d:a9 -> 0:1b:4f:3f:73:e0 rtcp_echo 0 in VLAN 0 out VLAN 0 Enc 0 Dec 0 Snt 0 Drp 0 Rx 0 Rly 0 ECH 0
[root@SD36SBCE ~]# showflow 310 dynamic 9
0 [10.10.48.58:2052 -> 10.10.48.192:35048] DecEna DEC srtp MKlen 10 SltLen e TlkSpt 0 SSRC[0] 74356e54{0} SSRC[1] 0{0} SSRC[2] 0{0} ROC[0] 0 ROC[1] 0 ROC[2] 0 sq[0] 411 sq[1] 0 sq[2] 0 EncEna ENC srtp MKlen 10 SltLen e TlkSpt 0 SSRC[0] 74356e54{0} SSRC[1] 0{0} SSRC[2] 0{0} ROC[0] 0 ROC[1] 0 ROC[2] 0 sq[0] 411 sq[1] 0 sq[2] 0 OUT 3 RELAY 10.10.32.60:35058 -> 162.248.168.235:43040 mac 0:c:29:30:7d:9f -> 20:23:51:b2:7e:50 rtcp_echo 0 in VLAN 0 out VLAN 0 Enc 411 Dec 411 Snt 0 Drp 0 Rx 411 Rly 411 ECH 0
0 [10.10.48.58:2053 -> 10.10.48.192:35049] OUT 3 RELAY 10.10.32.60:35059 -> 162.248.168.235:43041 mac 0:c:29:30:7d:9f -> 20:23:51:b2:7e:50 rtcp_echo 0 in VLAN 0 out VLAN 0 Enc 0 Dec 0 Snt 0 Drp 0 Rx d Rly d ECH 0
3 [162.248.168.235:43040 -> 10.10.32.60:35058] DecEna DEC srtp MKlen 10 SltLen e TlkSpt 0 SSRC[0] 896dec66{0} SSRC[1] 0{0} SSRC[2] 0{0} ROC[0] 0 ROC[1] 0 ROC[2] 0 sq[0] 7faf sq[1] 0 sq[2] 0 EncEna ENC srtp MKlen 10 SltLen e TlkSpt 0 SSRC[0] 896dec66{0} SSRC[1] 0{0} SSRC[2] 0{0} ROC[0] 0 ROC[1] 0 ROC[2] 0 sq[0] 7faf sq[1] 0 sq[2] 0 OUT 0 RELAY 10.10.48.192:35048 -> 10.10.48.58:2052 mac 0:c:29:30:7d:a9 -> 0:1b:4f:3f:73:e0 rtcp_echo 0 in VLAN 0 out VLAN 0 Enc 406 Dec 406 Snt 0 Drp 0 Rx 406 Rly 406 ECH 0
3 [162.248.168.235:43041 -> 10.10.32.60:35059] OUT 0 RELAY 10.10.48.192:35049 -> 10.10.48.58:2053 mac 0:c:29:30:7d:a9 -> 0:1b:4f:3f:73:e0 rtcp_echo 0 in VLAN 0 out VLAN 0 Enc 0 Dec 0 Snt 0 Drp 0 Rx 4 Rly 4 ECH 0
[root@SD36SBCE ~]# showflow 310 dynamic 9
0 [10.10.48.58:2050 -> 10.10.48.192:35052] DecEna DEC srtp MKlen 10 SltLen e TlkSpt 0 SSRC[0] 2f2e5a5b{0} SSRC[1] 0{0} SSRC[2] 0{0} ROC[0] 0 ROC[1] 0 ROC[2] 0 sq[0] 11f sq[1] 0 sq[2] 0 EncEna ENC srtp MKlen 10 SltLen e TlkSpt 0 SSRC[0] 2f2e5a5b{0} SSRC[1] 0{0} SSRC[2] 0{0} ROC[0] 0 ROC[1] 0 ROC[2] 0 sq[0] 11f sq[1] 0 sq[2] 0 OUT 3 RELAY 10.10.32.60:35060 -> 162.248.168.237:61032 mac 0:c:29:30:7d:9f -> 20:23:51:b2:7e:50 rtcp_echo 0 in VLAN 0 out VLAN 0 Enc 11f Dec 11f Snt 0 Drp 0 Rx 11f Rly 11f ECH 0
0 [10.10.48.58:2051 -> 10.10.48.192:35053] OUT 3 RELAY 10.10.32.60:35061 -> 162.248.168.237:61033 mac 0:c:29:30:7d:9f -> 20:23:51:b2:7e:50 rtcp_echo 0 in VLAN 0 out VLAN 0 Enc 0 Dec 0 Snt 0 Drp 0 Rx a Rly a ECH 0
3 [162.248.168.237:61032 -> 10.10.32.60:35060] DecEna DEC srtp MKlen 10 SltLen e TlkSpt 0 SSRC[0] b9da4882{0} SSRC[1] 0{0} SSRC[2] 0{0} ROC[0] 0 ROC[1] 0 ROC[2] 0 sq[0] 7ac7 sq[1] 0 sq[2] 0 EncEna ENC srtp MKlen 10 SltLen e TlkSpt 0 SSRC[0] b9da4882{0} SSRC[1] 0{0} SSRC[2] 0{0} ROC[0] 0 ROC[1] 0 ROC[2] 0 sq[0] 7ac7 sq[1] 0 sq[2] 0 OUT 0 RELAY 10.10.48.192:35052 -> 10.10.48.58:2050 mac 0:c:29:30:7d:a9 -> 0:1b:4f:3f:73:e0 rtcp_echo 0 in VLAN 0 out VLAN 0 Enc de Dec de Snt 0 Drp 0 Rx de Rly de ECH 0
3 [162.248.168.237:61033 -> 10.10.32.60:35061] OUT 0 RELAY 10.10.48.192:35053 -> 10.10.48.58:2051 mac 0:c:29:30:7d:a9 -> 0:1b:4f:3f:73:e0 rtcp_echo 0 in VLAN 0 out VLAN 0 Enc 0 Dec 0 Snt 0 Drp 0 Rx 2 Rly 2 ECH 0
[root@SD36SBCE ~]# showflow 310 dynamic 9
0 [10.10.48.58:2050 -> 10.10.48.192:35052] DecEna DEC srtp MKlen 10 SltLen e TlkSpt 0 SSRC[0] 2f2e5a5b{0} SSRC[1] 0{0} SSRC[2] 0{0} ROC[0] 0 ROC[1] 0 ROC[2] 0 sq[0] 30c sq[1] 0 sq[2] 0 EncEna ENC srtp MKlen 10 SltLen e TlkSpt 0 SSRC[0] 2f2e5a5b{0} SSRC[1] 0{0} SSRC[2] 0{0} ROC[0] 0 ROC[1] 0 ROC[2] 0 sq[0] 30c sq[1] 0 sq[2] 0 OUT 3 RELAY 10.10.32.60:35060 -> 162.248.168.237:61032 mac 0:c:29:30:7d:9f -> 20:23:51:b2:7e:50 rtcp_echo 0 in VLAN 0 out VLAN 0 Enc 30c Dec 30c Snt 0 Drp 0 Rx 30c Rly 30c ECH 0
0 [10.10.48.58:2051 -> 10.10.48.192:35053] OUT 3 RELAY 10.10.32.60:35061 -> 162.248.168.237:61033 mac 0:c:29:30:7d:9f -> 20:23:51:b2:7e:50 rtcp_echo 0 in VLAN 0 out VLAN 0 Enc 0 Dec 0 Snt 0 Drp 0 Rx c Rly c ECH 0
3 [162.248.168.237:61032 -> 10.10.32.60:35060] DecEna DEC srtp MKlen 10 SltLen e TlkSpt 0 SSRC[0] b9da4882{0} SSRC[1] 0{0} SSRC[2] 0{0} ROC[0] 0 ROC[1] 0 ROC[2] 0 sq[0] 7cb4 sq[1] 0 sq[2] 0 EncEna ENC srtp MKlen 10 SltLen e TlkSpt 0 SSRC[0] b9da4882{0} SSRC[1] 0{0} SSRC[2] 0{0} ROC[0] 0 ROC[1] 0 ROC[2] 0 sq[0] 7cb4 sq[1] 0 sq[2] 0 OUT 0 RELAY 10.10.48.192:35052 -> 10.10.48.58:2050 mac 0:c:29:30:7d:a9 -> 0:1b:4f:3f:73:e0 rtcp_echo 0 in VLAN 0 out VLAN 0 Enc 2cb Dec 2cb Snt 0 Drp 0 Rx 2cb Rly 2cb ECH 0
3 [162.248.168.237:61033 -> 10.10.32.60:35061] OUT 0 RELAY 10.10.48.192:35053 -> 10.10.48.58:2051 mac 0:c:29:30:7d:a9 -> 0:1b:4f:3f:73:e0 rtcp_echo 0 in VLAN 0 out VLAN 0 Enc 0 Dec 0 Snt 0 Drp 0 Rx 4 Rly 4 ECH 0

"""

