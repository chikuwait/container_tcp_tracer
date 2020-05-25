from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    print("%-6d %-16s" %  (event.pid, event.comm))

bpf = BPF(src_file = "trace.c");
bpf.attach_kprobe(event = "tcp_v4_connect", fn_name = "tcp_connect")
bpf.attach_kretprobe(event = "tcp_v4_connect", fn_name = "tcp_connect_ret")
bpf["events"].open_perf_buffer(print_event)

while 1:
    bpf.perf_buffer_poll()

