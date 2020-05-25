#include <uapi/linux/ptrace.h>
#include <net/sock.h>

BPF_HASH(socklist, u32, struct sock *);

int tcp_connect(struct pt_regs *ctx, struct sock *sock){
    u32 pid = bpf_get_current_pid_tgid();
    socklist.update(&pid, &sock);
    return 0;
}

int tcp_connect_ret(struct pt_regs *ctx){
    u32 pid = bpf_get_current_pid_tgid();
    struct sock **sock = socklist.lookup(&pid);

    if (sock == 0){
        return 0;
    }
    bpf_trace_printk("test\n");

    socklist.delete(&pid);
    return 0;
}
