 
// @Autor: Pasquale Caporaso
// This is an example program showed at Linux Day 2022 - Roma Tor Vergata

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 

#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/sched.h>

//probe limits
#define MAX_PERCPU_BUFSIZE  (1 << 15) // set by the kernel as an upper bound
#define MAX_BUFFERS         2
#define MAX_STRING_SIZE     4096

//kernel limits
#define MAX_NAME_SIZE       128

//useful costants
#define RETURN_BUFFER       0
#define TEMP_BUFFER         1

//useful macros
#define READ_KERN(ptr)                                                                         \
    ({                                                                                         \
        typeof(ptr) _val;                                                                      \
        __builtin_memset((void *) &_val, 0, sizeof(_val));                                     \
        bpf_probe_read((void *) &_val, sizeof(_val), &ptr);                                    \
        _val;                                                                                  \
    })

//structs
typedef struct simple_buf {
    u8 buf[MAX_PERCPU_BUFSIZE];
} buf_t;

typedef struct return_info {
    pid_t pid;
    u8 filename[MAX_NAME_SIZE];
} return_info_t;

//maps
BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(bufs, buf_t, MAX_BUFFERS);

// ebpf probe
int open_file_probe(struct pt_regs *ctx) {

    //check owner
    struct task_struct* ts = (struct task_struct *)bpf_get_current_task();
    if (ts->cred->uid.val == 0 || ts->cred->euid.val == 0)
        return 0;
        
    // prepare return buffer
    int idx = RETURN_BUFFER;
    return_info_t* info = (return_info_t*) bufs.lookup(&idx);
    if (info == NULL)
        return 0;

    // get pid
    u32 pid = bpf_get_current_pid_tgid();
    info->pid = pid;

    // get file path
    char* filename = (char*) PT_REGS_PARM2(ctx);
    if (filename == NULL)
        return 0;

    // move path to return buffer
    bpf_probe_read_user(info->filename, MAX_NAME_SIZE, filename);

    // look at /sys/kernel/debug/tracing/trace_pipe
    bpf_trace_printk("translated string: %s\\n", info->filename);
    
    // submit event
    int rc;
    if ((rc = events.perf_submit(ctx, info, sizeof(return_info_t))) < 0)
        bpf_trace_printk("perf_output failed: %d\\n", rc);

    return 0;

}