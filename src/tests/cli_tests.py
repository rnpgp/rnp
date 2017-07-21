#!/usr/bin/python

import sys
import distutils.spawn
import tempfile
import os
from os import path
import shutil
import subprocess
import re
from subprocess import Popen, PIPE
from cli_common import find_utility, run_proc, pswd_pipe

RNP = ''
RNPK = ''
GPG = ''
RNPDIR = ''
PASSWORD = 'password'
#RE_RSA_KEY = r'(?ms)# off=0 ctb=c6 tag=6 hlen=3 plen=\d+ new-ctb\s+.*'

RE_RSA_KEY = r'^\s*' \
r'# off=0 ctb=c6 tag=6 hlen=3 plen=\d+ new-ctb\s+' \
r':public key packet:\s+' \
r'version 4, algo 1, created \d+, expires 0\s+' \
r'pkey\[0\]: \[204[0-8] bits\]\s+' \
r'pkey\[1\]: \[17 bits\]\s+' \
r'keyid: ([0-9A-F]{16})\s+' \
r'# off=\d+ ctb=cd tag=13 hlen=\d+ plen=\d+ new-ctb\s+' \
r':user ID packet: "rsa@rnp"\s+' \
r'# off=\d+ ctb=c2 tag=2 hlen=3 plen=\d+ new-ctb\s+' \
r':signature packet: algo 1, keyid \1\s+' \
r'version 4, created \d+, md5len 0, sigclass 0x13\s+' \
r'digest algo 8, begin of digest [0-9a-f\s]{5}\s+' \
r'hashed subpkt 2 len 4 \(sig created .+\)\s+' \
r'hashed subpkt 16 len 8 \(issuer key ID \1\)\s+' \
r'hashed subpkt 25 len 1 \(primary user ID\)\s+' \
r'data: \[204[0-8] bits\]$'

def setup():
    return

def run_rnp_tests():
    
    return

def check_packets(fname, regexp):
    global GPG

    retcode, output, err = run_proc(GPG, ['--list-packets', fname])
    if retcode != 0:
        print err
        return False
    else:
        result = re.match(regexp, output)
        if result:
            return True
        else:
            print 'Wrong packets: \n' + output
            return False

def rnpkey_generate_rsa():
    retcode, output, err = run_proc(RNPK, ['--homedir', RNPDIR, '--pass-fd', str(pswd_pipe(PASSWORD)), '--userid', 'rsa@rnp', '--generate-key'])

    if retcode != 0:
        print err
        raise NameError('key generation failed')
    if not check_packets(path.join(RNPDIR, 'pubring.gpg'), RE_RSA_KEY):
        raise NameError('generated key check failed')

    return

def run_rnpkeys_tests():
    # Setting up directories
    global RNPDIR, RNPK, GPG
    RNPDIR = path.join(os.getcwd(), '.rnp')
    RNPK = find_utility('rnpkeys')
    GPG = find_utility('gpg')
    os.mkdir(RNPDIR, 0700)

    # 1. Generate default RSA key
    rnpkey_generate_rsa()

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