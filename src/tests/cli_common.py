import sys
import distutils.spawn
import random
import string
import logging
import os
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

def raise_err(msg, log = None):
    raise CLIError(msg, log)

def size_to_readable(num, suffix = 'B'):
    for unit in ['','K','M','G','T','P','E','Z']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)

def pswd_pipe(password):
    pr, pw = os.pipe()
    with os.fdopen(pw, 'w') as fw:
        fw.write(password)
        fw.write('\n')
        fw.write(password)

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

def run_proc(proc, params):
    logging.debug((proc + ' ' + ' '.join(params)).strip())
    process = Popen([proc] + params, stdout=PIPE, stderr=PIPE)
    output, errout = process.communicate()
    retcode = process.poll()
    logging.debug(errout.strip())
    logging.debug(output.strip())

    return (retcode, output, errout)

def run_proc_fast(proc, params):
    with open(os.devnull, 'w') as devnull:
        proc = Popen([proc] + params, stdout=devnull, stderr=devnull)
    return proc.wait()
