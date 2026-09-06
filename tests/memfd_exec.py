#!/usr/bin/env python3
"""Spawn a process whose executable only ever existed in memory.

Used by the fileless detector test. A shebang script in a memfd would not do:
for an interpreted file /proc/<pid>/exe points at the interpreter, so the copy
has to be a real ELF. The child then reads "/memfd:... (deleted)", which is
what a dropper that never touches the disk looks like.

argv[1] is a file to write the child's pid to.
"""
import os
import shutil
import sys
import time

src = next((p for p in ("/bin/sleep", "/usr/bin/sleep") if os.path.exists(p)), None)
if src is None:
    sys.exit("no sleep binary to copy")

fd = os.memfd_create("cerberus-test")
with open(src, "rb") as fh:
    shutil.copyfileobj(fh, os.fdopen(os.dup(fd), "wb"))
os.fchmod(fd, 0o700)

pid = os.fork()
if pid == 0:
    try:
        os.execv(f"/proc/self/fd/{fd}", ["cerberus-memfd-test", "300"])
    finally:
        os._exit(127)

with open(sys.argv[1], "w") as fh:
    fh.write(str(pid))
time.sleep(30)
