 
// @Autor: Pasquale Caporaso
// This is an example program showed at Linux Day 2022 - Roma Tor Vergata

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 


#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/sched.h>
//#include "helpers.h"

//probe limits
#define MAX_PERCPU_BUFSIZE  (1 << 15) // set by the kernel as an upper bound
#define MAX_BUFFERS         2
#define MAX_STRING_SIZE     4096

//kernel limits
#define MAX_PATH_COMPONENTS 48
#define MAX_NAME_SIZE       128
#define MAX_PATH            4096

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
    char directory[MAX_PATH];
} return_info_t;

//maps
BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(bufs, buf_t, MAX_BUFFERS);

//https://github.com/aquasecurity/tracee/blob/main/pkg/ebpf/c/tracee.bpf.c#L2297
static __always_inline void *get_dentry_path_str(buf_t* string_p, struct dentry *dentry)
{
    char slash = '/';
    int zero = 0;

    u32 buf_off = (MAX_PERCPU_BUFSIZE >> 1);

#pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        struct dentry *d_parent = READ_KERN(dentry->d_parent);
        if (dentry == d_parent) {
            break;
        }
        // Add this dentry name to path
        struct qstr d_name = READ_KERN(dentry->d_name);
        unsigned int len = (d_name.len + 1) & (MAX_STRING_SIZE - 1);
        unsigned int off = buf_off - len;
        // Is string buffer big enough for dentry name?
        int sz = 0;
        if (off <= buf_off) { // verify no wrap occurred
            len = len & ((MAX_PERCPU_BUFSIZE >> 1) - 1);
            sz = bpf_probe_read_str(
                &(string_p->buf[off & ((MAX_PERCPU_BUFSIZE >> 1) - 1)]), len, (void *) d_name.name);
        } else
            break;
        if (sz > 1) {
            buf_off -= 1; // remove null byte termination with slash sign
            bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &slash);
            buf_off -= sz - 1;
        } else {
            // If sz is 0 or 1 we have an error (path can't be null nor an empty string)
            break;
        }
        dentry = d_parent;
    }

    if (buf_off == (MAX_PERCPU_BUFSIZE >> 1)) {
        // memfd files have no path in the filesystem -> extract their name
        buf_off = 0;
        struct qstr d_name = READ_KERN(dentry->d_name);
        bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, (void *) d_name.name);
    } else {
        // Add leading slash
        buf_off -= 1;
        bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &slash);
        // Null terminate the path string
        bpf_probe_read(&(string_p->buf[(MAX_PERCPU_BUFSIZE >> 1) - 1]), 1, &zero);
    }

    return &string_p->buf[buf_off];
}

// ebpf probe
int open_folder_sniffer(struct pt_regs *ctx) {

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
    
    // get info on the directory
    struct file* dentry_file = (struct file*) PT_REGS_PARM1(ctx);
    if (dentry_file == NULL)
        return 0;
    
    // get per-cpu temp buffer
    idx = TEMP_BUFFER;
    buf_t *string_p = bufs.lookup(&idx);
    if (string_p == NULL)
        return 0;

    // translate
    char* path_string = get_dentry_path_str(string_p, dentry_file->f_path.dentry);
    
    // look at /sys/kernel/debug/tracing/trace_pipe
    bpf_trace_printk("translated string: %s\\n", path_string);
    
    // move path to return buffer
    bpf_probe_read(info->directory, MAX_PATH, path_string);

    // submit event
    int rc;
    if ((rc = events.perf_submit(ctx, info, sizeof(return_info_t))) < 0)
        bpf_trace_printk("perf_output failed: %d\\n", rc);

    return 0;

}