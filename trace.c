#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/sched.h>

struct data_t{
    u32 pid;
    char comm[TASK_COMM_LEN];
};
BPF_HASH(socklist, u32, struct sock *);
BPF_PERF_OUTPUT(events);


int tcp_connect(struct pt_regs *ctx, struct sock *sock){
    u32 pid = bpf_get_current_pid_tgid();
    socklist.update(&pid, &sock);

    return 0;
}

int tcp_connect_ret(struct pt_regs *ctx){
    u32 pid = bpf_get_current_pid_tgid();
    struct sock **sock;
    struct data_t data = {};

    sock = socklist.lookup(&pid);    
    if(sock == 0 ){
        return 0;
    }

    data.pid = pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
    socklist.delete(&pid);

    return 0;
}
