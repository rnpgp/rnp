import sys
import distutils.spawn
import tempfile
from os import path
import os
import shutil
from subprocess import Popen, PIPE
from timeit import default_timer as perf_timer

def size_to_readable(num, suffix = 'B'):
    for unit in ['','K','M','G','T','P','E','Z']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)

def pswd_pipe(passphrase):
    pr, pw = os.pipe()
    with os.fdopen(pw, 'w') as fw:
        fw.write(passphrase)
    return pr

def find_utility(name, exitifnone = True):
    path = distutils.spawn.find_executable(name)
    if not path and exitifnone:
        print 'Cannot find utility {}. Exiting.'.format(name)
        sys.exit(1)

    return path

def run_proc(proc, params):
    process = Popen([proc] + params, stdout=PIPE, stderr=PIPE)
    output, errout = process.communicate()
    retcode = process.poll()

    return (retcode, output, errout)
