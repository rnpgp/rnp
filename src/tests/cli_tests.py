#!/usr/bin/python

import sys
import distutils.spawn
import tempfile
from os import path
import os
import shutil
import subprocess
from subprocess import Popen, PIPE
from cli_common import find_utility, run_proc, pswd_pipe

def setup():
    return

def run_rnp_tests():
    
    return

def run_rnpkeys_tests():
    RNPDIR = path.join(os.getcwd(), '.rnp')
    RNPK = find_utility('rnpkeys')
    os.mkdir(RNPDIR, 0700)

    retcode, output, err = run_proc(RNPK, ['--homedir', RNPDIR, '--pass-fd', str(pswd_pipe('password')), '--userid', 'rsa@rnp', '--generate-key'])

    if retcode != 0:
        print err
        raise NameError('rnpkeys failed')
    else:
        print output

    return

def run_tests():
    if not len(sys.argv) == 2:
        print "Wrong usage. Run cli_tests [rnp | rnpkeys]"
        sys.exit(1)

    if sys.argv[1] == 'rnp':
        run_rnp_tests()
    elif sys.argv[1] == 'rnpkeys':
        run_rnpkeys_tests()
    else:
        print "Wrong parameter {}".format(sys.argv[1])
        sys.exit(1)

    return

def cleanup():
    return

if __name__ == '__main__':
    setup()
    run_tests()
    cleanup()