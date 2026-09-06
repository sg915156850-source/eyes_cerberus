#!/usr/bin/env python3
"""Spawn a process whose executable only ever existed in memory.

Used by the fileless detector test. A shebang script in a memfd would not do:
for an interpreted file /proc/<pid>/exe points at the interpreter, so the copy
has to be a real ELF. The child then reads "/memfd:... (deleted)", which is
what a dropper that never touches the disk looks like.

The copy goes through os.write rather than a buffered file object: a buffered
writer is not guaranteed to have been flushed before the fork, and an empty
memfd makes execv fail with ENOEXEC -- which showed up as a detector test
failing on one distribution and passing on another.

argv[1] is a file to write the child's pid to. Nothing is written if the child
did not survive, so the caller can skip rather than fail.
"""
import os
import sys
import time

src = next((p for p in ("/bin/sleep", "/usr/bin/sleep") if os.path.exists(p)), None)
if src is None:
    sys.exit("no sleep binary to copy")

with open(src, "rb") as fh:
    payload = fh.read()

fd = os.memfd_create("cerberus-test")
written = 0
while written < len(payload):
    written += os.write(fd, payload[written:])
os.fchmod(fd, 0o700)

pid = os.fork()
if pid == 0:
    try:
        os.execv(f"/proc/self/fd/{fd}", ["cerberus-memfd-test", "300"])
    finally:
        os._exit(127)

# Only claim the child if it actually got off the ground.
time.sleep(0.3)
alive = False
try:
    dead, status = os.waitpid(pid, os.WNOHANG)
    alive = dead == 0
except ChildProcessError:
    alive = False

if not alive:
    sys.exit("child did not survive execv from the memfd")

with open(sys.argv[1], "w") as fh:
    fh.write(str(pid))
time.sleep(30)
