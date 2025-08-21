import os
import fcntl

def acquire_lock(lock_file):
    try:
        lock_fd = open(lock_file, 'w')
        fcntl.lockf(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return lock_fd
    except IOError:
        if 'lock_fd' in locals():
            lock_fd.close()
        return None

def release_lock(lock_fd, lock_file):
    if lock_fd:
        fcntl.lockf(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()
        try:
            os.remove(lock_file)
        except OSError:
            pass
