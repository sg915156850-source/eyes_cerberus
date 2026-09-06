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

argv[1] is a file to write the child's pid to; this process then exits and the
child is reparented. Nothing is written if the child did not survive, so the
caller can skip rather than fail -- and the caller kills the pid it was given.
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
        # argv[0] stays "sleep": some distributions ship coreutils-single,
        # where /bin/sleep is a symlink into one multicall binary that
        # dispatches on argv[0] and exits immediately under any other name.
        os.execv(f"/proc/self/fd/{fd}", ["sleep", "300"])
    finally:
        os._exit(127)


def child_ok():
    """The child is alive AND its exe really reads as an anonymous memfd."""
    try:
        reaped, _ = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return False
    if reaped != 0:
        return False
    try:
        return "memfd:" in os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return False


# Assert the precondition here rather than leaving the test to infer it from a
# missing finding: if this environment cannot produce a memfd process, the test
# should skip, not fail.
for _ in range(20):
    if child_ok():
        break
    time.sleep(0.1)
else:
    sys.exit("could not get a live process running from a memfd")

# Write the pid and get out of the way. The child does not need this process:
# it is a plain sleep(1) and survives reparenting, and the test kills it by pid
# when it is done. Hanging around for 30 seconds only made the suite wait.
with open(sys.argv[1], "w") as fh:
    fh.write(str(pid))
