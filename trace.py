from bcc import BPF
from bcc.utils import printb

bpf = BPF(src_file = "trace.c");
bpf.attach_kprobe(event = "tcp_v4_connect", fn_name = "tcp_connect")
bpf.attach_kretprobe(event = "tcp_v4_connect", fn_name = "tcp_connect_ret")

print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
