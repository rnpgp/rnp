#!/usr/bin/python

import sys
import tempfile
from os import path
import os
import shutil
import subprocess
from timeit import default_timer as perf_timer
from cli_common import find_utility, run_proc, pswd_pipe, rnp_file_path, random_text, file_text, size_to_readable

RNP = ''
RNPK = ''
GPG = ''
WORKDIR = ''
RNPDIR = ''
GPGDIR = ''
RMWORKDIR = False
SMALL_ITERATIONS = 30
LARGE_ITERATIONS = 5
LARGESIZE = 1024*1024*100
SMALLSIZE = 0
SMALLFILE = 'smalltest.txt'
LARGEFILE = 'largetest.txt'
PASSWORD = 'password'

def run_proc_iterative(proc, params, iterations = 1, nooutput = True):
    fnull = open(os.devnull, 'w') if nooutput else None

    tstart = perf_timer()
    for i in range(0, iterations):
        ret = subprocess.call([proc] + params, stderr = fnull, stdout = fnull)
        if ret != 0:
            print 'Failed to call {} {} : return code {}'.format(proc, params, ret)
            return
    
    tm = perf_timer() - tstart

    return tm

def setup():
    # Searching for rnp and gnupg
    global RNP, GPG, RNPK, WORKDIR, RNPDIR, GPGDIR, SMALLSIZE, RMWORKDIR
    RNP = rnp_file_path('src/rnp/rnp')
    RNPK = rnp_file_path('src/rnpkeys/rnpkeys')
    GPG = find_utility('gpg')
    WORKDIR = os.getcwd()
    if not '/tmp/' in WORKDIR:
        WORKDIR = tempfile.mkdtemp(prefix = 'rnpptmp')
        RMWORKDIR = True

    print 'Setting up test in {} ...'.format(WORKDIR)

    # Creating working directory and populating it with test files
    RNPDIR = path.join(WORKDIR, '.rnp')
    GPGDIR = path.join(WORKDIR, '.gpg')
    os.mkdir(RNPDIR, 0700)
    os.mkdir(GPGDIR, 0700)

    # Generating key
    pipe = pswd_pipe(PASSWORD) 
    params = ['--homedir', RNPDIR, '--pass-fd', str(pipe), '--userid', 'performance@rnp', '--generate-key']
    # Run key generation
    ret, out, err = run_proc(RNPK, params)
    os.close(pipe)

    # Importing keys to GnuPG so it can build trustdb and so on
    ret, out, err = run_proc(GPG, ['--batch', '--passphrase', '', '--homedir', GPGDIR, '--import', path.join(RNPDIR, 'pubring.gpg'), path.join(RNPDIR, 'secring.gpg')])

    # Generating small file for tests
    SMALLSIZE = 3312;
    st = 'lorem ipsum dol ' * (SMALLSIZE/16)
    with open(path.join(WORKDIR, SMALLFILE), 'w+') as small_file:
        small_file.write(st)

    # Generating large file for tests
    print 'Generating large file of size {}'.format(size_to_readable(LARGESIZE))
    st = '0123456789ABCDEF' * (1024/16)
    with open(path.join(WORKDIR, LARGEFILE), 'w') as fd:
        for i in range(0, LARGESIZE / 1024 - 1):
            fd.write(st)

    return

def generate_keys():
    return

def run_rnp_and_gpg(rnpparams, gpgparams, iterations = 1):
    trnp = run_proc_iterative(RNP, rnpparams, iterations)
    if not trnp:
        return
    tgpg = run_proc_iterative(GPG, gpgparams, iterations)
    if not tgpg:
        return

    return [trnp, tgpg]

def print_test_results(fsize, iterations, rnptime, gpgtime, operation):
    if not rnptime or not gpgtime:
        print '{}:TEST FAILED'.format(operation)
        return

    if fsize == SMALLSIZE:        
        print '{}:RNP:{:.2f} runs/sec'.format(operation, iterations / rnptime)
        print '{}:GPG:{:.2f} runs/sec'.format(operation, iterations / gpgtime)
    else:
        print '{}:RNP:{:.2f} MB/sec'.format(operation, fsize * iterations / 1024.0 / 1024.0 / rnptime)
        print '{}:GPG:{:.2f} MB/sec'.format(operation, fsize * iterations / 1024.0 / 1024.0 / gpgtime)
    
    print '{}:RNP vs GPG:{:.2f}'.format(operation, rnptime/gpgtime)

    return

def run_tests():
    rnphome = ['--homedir', RNPDIR]
    gpghome = ['--homedir', GPGDIR]

    # Running each operation iteratively for a small and large file(s), calculating the average
    for filesize in ['small', 'large']:
        if filesize == 'small':
            infile, outfile, iterations, fsize = (SMALLFILE, SMALLFILE + '.gpg', SMALL_ITERATIONS, SMALLSIZE)
        else:            
            infile, outfile, iterations, fsize = (LARGEFILE, LARGEFILE + '.gpg', LARGE_ITERATIONS, LARGESIZE)

        infile = path.join(WORKDIR, infile)
        rnpout = path.join(WORKDIR, outfile + '.rnp')
        gpgout = path.join(WORKDIR, outfile + '.gpg')

        print 'Running tests for {} file, iterations {}'.format(filesize, iterations)
        # 1. Encryption
        print '#1. Encryption'
        tmrnp = run_proc_iterative(RNP, rnphome + ['--encrypt', infile, '--output', rnpout], iterations, nooutput = False)
        tmgpg = run_proc_iterative(GPG, gpghome + ['--batch', '--yes', '--trust-model', 'always', '-r', 'performance@rnp', '--compress-level', '0', '--output', gpgout, '--encrypt', infile], iterations, nooutput = False)
        print_test_results(fsize, iterations, tmrnp, tmgpg, 'ENCRYPT')

        # 2. Decryption
        #print '\n#2. Decryption\n'
        # 3. Signing
        #print '\n#3. Signing\n'
        # 4. Verification
        #print '\n#4. Verification\n'
        # 5. Cleartext signing
        #print '\n#5. Cleartext signing and verification\n'
        # 6. Detached signature
        #print '\n#6. Detached signing and verification\n'

    return

def cleanup():
    try:
        shutil.rmtree(WORKDIR)
    except:
        pass
    return

if __name__ == '__main__':
    setup()
    run_tests()
    cleanup()