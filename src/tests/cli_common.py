import sys
import distutils.spawn
import random
import string
import logging
import os
import platform
import re
from os import path
from subprocess import Popen, PIPE

RNP_ROOT = None

class CLIError(Exception):
    def __init__(self, message, log = None):
        super(Exception, self).__init__(message)
        self.log = log

    def __str__(self):
        logging.info(self.message)
        logging.debug(self.log.strip())

def is_windows():
    return sys.platform.startswith('win') or sys.platform.startswith('msys')

def path_for_gpg(path):
    # GPG built for mingw/msys doesn't work with Windows pathes
    if re.match(r'^[a-z]:[\\\/].*', path.lower()):
        path = '/' + path[0] + '/' + path[3:].replace('\\', '/')
    return path

def raise_err(msg, log = None):
    raise CLIError(msg, log)

def size_to_readable(num, suffix = 'B'):
    for unit in ['','K','M','G','T','P','E','Z']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)

def list_upto(lst, count):
    res = lst[:]
    while len(res) < count:
        res = res + lst[:]
    return res[:count]

def pswd_pipe(password):
    pr, pw = os.pipe()
    with os.fdopen(pw, 'w') as fw:
        fw.write(password)
        fw.write('\n')
        fw.write(password)

    if not is_windows():
        return pr
    # On Windows pipe is not inheritable so dup() is needed
    prd = os.dup(pr)
    os.close(pr)
    return prd

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
        logging.error('Cannot find utility {}. Exiting.'.format(name))
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

def run_proc_windows(proc, params, stdin=None):
    logging.debug((proc + ' ' + ' '.join(params)).strip())
    exe = os.path.basename(proc)
    # Not sure why but empty string is not passed to underlying spawnv call
    params = map(lambda st: st if st else '""', [exe] + params)
    sys.stdout.flush()

    # We may use pipes here (ensuring we use dup to inherit handles), but those have limited buffer
    # so we'll need to poll process
    if stdin:
        with open('stdin.txt', "wb+") as stdinf:
            stdinf.write(stdin)
        stdin_fl = os.open('stdin.txt', os.O_RDONLY | os.O_BINARY)
        stdin_no = sys.stdin.fileno()
        stdin_cp = os.dup(stdin_no)
    stdout_fl = os.open('stdout.txt', os.O_CREAT | os.O_RDWR | os.O_BINARY)
    stdout_no = sys.stdout.fileno()
    stdout_cp = os.dup(stdout_no)
    stderr_fl = os.open('stderr.txt', os.O_CREAT | os.O_RDWR | os.O_BINARY)
    stderr_no = sys.stderr.fileno()
    stderr_cp = os.dup(stderr_no)

    try:
        os.dup2(stdout_fl, stdout_no)
        os.close(stdout_fl)
        os.dup2(stderr_fl, stderr_no)
        os.close(stderr_fl)
        if stdin:
            os.dup2(stdin_fl, stdin_no)
            os.close(stdin_fl)
        retcode = os.spawnv(os.P_WAIT, proc, params)
    finally:
        os.dup2(stdout_cp, stdout_no)
        os.close(stdout_cp)
        os.dup2(stderr_cp, stderr_no)
        os.close(stderr_cp)
        if stdin:
            os.dup2(stdin_cp, stdin_no)
            os.close(stdin_cp)
    out = file_text('stdout.txt').replace('\r\n', '\n')
    err = file_text('stderr.txt').replace('\r\n', '\n')
    os.unlink('stdout.txt')
    os.unlink('stderr.txt')
    if stdin: 
        os.unlink('stdin.txt')
    logging.debug(err.strip())
    logging.debug(out.strip())
    return (retcode, out, err)

def run_proc(proc, params, stdin=None):
    # On Windows we need to use spawnv() for handle inheritance in pswd_pipe()
    if is_windows():
        return run_proc_windows(proc, params, stdin)

    logging.debug((proc + ' ' + ' '.join(params)).strip())
    process = Popen([proc] + params, stdout=PIPE, stderr=PIPE, stdin=PIPE if stdin else None)
    output, errout = process.communicate(stdin)
    retcode = process.poll()
    logging.debug(errout.strip())
    logging.debug(output.strip())

    return (retcode, output, errout)

def run_proc_fast(proc, params):
    with open(os.devnull, 'w') as devnull:
        proc = Popen([proc] + params, stdout=devnull, stderr=devnull)
    return proc.wait()
