import sys
import distutils.spawn
import tempfile
from os import path
import os
import shutil
import random
import string
from subprocess import Popen, PIPE
from timeit import default_timer as perf_timer

RNP_ROOT = None
DEBUG = False

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
        fw.write('\n')
        fw.write(passphrase)
        
    return pr

def random_text(path, size):
    # Generate random text, with 50% probability good-compressible
    if random.randint(0, 10) < 5:
        st = ''.join(random.choice(string.ascii_letters + string.digits + " \t\n-,.") for _ in range(size))
    else:
        st = ''.join(random.choice("abcdef0123456789 \t\n-,.") for _ in range(size))
    with open(path, 'w+') as f:
        f.write(st)

def file_text(path):
    with open(path, 'r') as f:
        return f.read()

def find_utility(name, exitifnone = True):
    path = distutils.spawn.find_executable(name)
    if not path and exitifnone:
        print 'Cannot find utility {}. Exiting.'.format(name)
        sys.exit(1)

    return path

def rnp_file_path(relpath, check = True):
    global RNP_ROOT
    if not RNP_ROOT:
        pypath = path.dirname(__file__)
        RNP_ROOT = path.realpath(path.join(pypath, '../..'))

    fpath = path.realpath(path.join(RNP_ROOT, relpath))

    if check and not os.path.isfile(fpath):
        raise NameError('rnp: file ' + relpath + ' not found')

    return fpath

def run_proc(proc, params):
    if DEBUG:
        sys.stderr.write(proc + ' ' + ' '.join(params) + '\n')
    process = Popen([proc] + params, stdout=PIPE, stderr=PIPE)
    output, errout = process.communicate()
    retcode = process.poll()
    if DEBUG:
        print errout
        print output

    return (retcode, output, errout)

