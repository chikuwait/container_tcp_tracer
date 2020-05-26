from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
def ntoa(addr):
    ipaddr = b''
    for n in range(0, 4):
        ipaddr = ipaddr + str(addr & 0xff).encode()
        if (n != 3):
            ipaddr = ipaddr + b'.'
        addr = addr >> 8
    return ipaddr

def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    print("%-6d %-s %-16s %-s %-s %-d" %  (event.pid, event.nodename, event.comm, ntoa(event.saddr), ntoa(event.daddr), event.dport))

bpf = BPF(src_file = "trace.c");
bpf.attach_kprobe(event = "tcp_v4_connect", fn_name = "tcp_connect")
bpf.attach_kretprobe(event = "tcp_v4_connect", fn_name = "tcp_connect_ret")
bpf["events"].open_perf_buffer(print_event)

while 1:
    bpf.perf_buffer_poll()

