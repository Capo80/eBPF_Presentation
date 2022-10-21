#!/usr/bin/python
# 
# @Autor: Pasquale Caporaso
# This is an example program showed at Linux Day 2022 - Roma Tor Vergata
#
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 

from bcc import BPF
from bcc.utils import printb
import os, signal
import ctypes as ct

# struct of the data returned by the probe
MAX_NAME_SIZE=128
class EventInfo(ct.Structure):
    _fields_ = [
                ("pid", ct.c_int),
                ("filename", ct.c_char*MAX_NAME_SIZE),
                ]

# this function weill be called every time an event happens
def perf_callback(cpu, data, size):
    assert size >= ct.sizeof(EventInfo)
    event = ct.cast(data, ct.POINTER(EventInfo)).contents

    print(event.pid, " opened file: ", event.filename)
        


# load BPF program
b = BPF(src_file="ebpf_probe.c")
b.attach_kprobe(event="do_sys_openat2", fn_name="open_file_probe")

# attach callback
b["events"].open_perf_buffer(perf_callback)

# listen for events
print("Waiting for events... Hit Ctrl-C to end.")
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
