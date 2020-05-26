#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/sched.h>
#include <linux/utsname.h>
#include <linux/pid_namespace.h>

struct data_t{
    u32 pid;
    char comm[TASK_COMM_LEN];
    u32 saddr;
    u32 daddr;
    u16 dport;
    int level;
    char nodename[64];
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
    struct sock **sock, *sockp;
    struct data_t data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct pid_namespace *pidns = (struct pid_namespace * )task->nsproxy->pid_ns_for_children;
    struct uts_namespace *uts = (struct uts_namespace * )task->nsproxy->uts_ns;

    sock = socklist.lookup(&pid);    
    if(sock == 0 || pidns->level == 0){
        return 0;
    }

    sockp = *sock;
    data.pid = pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.saddr = sockp->__sk_common.skc_rcv_saddr;
    data.daddr = sockp->__sk_common.skc_daddr;
    data.dport = sockp->__sk_common.skc_dport;
    data.level = pidns->level;
    bpf_probe_read(&data.nodename, sizeof(data.nodename), (void *)uts->name.nodename);

    events.perf_submit(ctx, &data, sizeof(data));
    socklist.delete(&pid);
    return 0;
}
