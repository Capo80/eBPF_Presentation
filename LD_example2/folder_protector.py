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

MAX_PATH=4096
class EventInfo(ct.Structure):
    _fields_ = [
                ("pid", ct.c_int),
                ("directory_path", ct.c_char*MAX_PATH),
                ]

def perf_callback(cpu, data, size):
    assert size >= ct.sizeof(EventInfo)
    event = ct.cast(data, ct.POINTER(EventInfo)).contents

    if (event.directory_path == b'/capo80/Documents/very_important_file.jpeg'):
        print(event.pid, " opened protected file: ", event.directory_path)
        os.kill(event.pid, signal.SIGKILL)


# load BPF program
b = BPF(src_file="folder_sniffer.c")
b.attach_kprobe(event="security_file_open", fn_name="open_folder_sniffer")

# attach callback
b["events"].open_perf_buffer(perf_callback)

# listen for events
print("Waiting for events... Hit Ctrl-C to end.")
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
