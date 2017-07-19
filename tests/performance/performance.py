#!/usr/bin/python

import sys
import distutils.spawn
import tempfile
from os import path
import os
import shutil
import subprocess
from timeit import default_timer as perf_timer

RNP = 'rnp'
RNP_KEYS = 'rnpkeys'
GPG = 'gpg2'
WORKDIR = '/tmp'
SMALL_ITERATIONS = 10
LARGE_ITERATIONS = 2
LARGESIZE = 1024*1024*100
SMALLSIZE = 0
SMALLFILE = 'smalltest.txt'
LARGEFILE = 'largetest.txt'

def size_to_readable(num, suffix = 'B'):
    for unit in ['','K','M','G','T','P','E','Z']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)

def find_utility(name, exitifnone = True):
    path = distutils.spawn.find_executable(name)
    if not path and exitifnone:
        print 'Cannot find utility {}. Exiting.'.format(name)
        sys.exit()

    return path

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
    global RNP, GPG, RNP_KEYS, WORKDIR, SMALLSIZE
    RNP = find_utility(RNP)
    GPG = find_utility(GPG)
    RNP_KEYS = find_utility(RNP_KEYS)

    # Creating working directory and populating it with test files
    WORKDIR = tempfile.mkdtemp()
    rnpdir = path.join(WORKDIR, '.rnp')
    gpgdir = path.join(WORKDIR, '.gnupg')
    os.mkdir(rnpdir, 0700)
    os.mkdir(gpgdir, 0700)

    print 'Copying test data to {} ...'.format(WORKDIR)

    srcpath = os.path.dirname(os.path.realpath(__file__))
    for fname in ['pubring.gpg', 'secring.gpg']:
        shutil.copyfile(path.join(srcpath, fname), path.join(rnpdir, fname))
        
    shutil.copyfile(path.join(srcpath, SMALLFILE), path.join(WORKDIR, SMALLFILE))
    SMALLSIZE = path.getsize(path.join(srcpath, SMALLFILE))

    # Importing keys to GnuPG so it can build trustdb and so on
    run_proc_iterative(GPG, ['--batch', '--passphrase', '', '--homedir', gpgdir, '--import', path.join(rnpdir, 'pubring.gpg'), path.join(rnpdir, 'secring.gpg')])

    # Generating large file for tests
    print 'Generating large file of size {}'.format(size_to_readable(LARGESIZE))
    fd = open(path.join(WORKDIR, LARGEFILE), 'w')
    st = '0123456789ABCDEF' * (1024/16)
    for i in range(0, LARGESIZE / 1024 - 1):
        fd.write(st)
    fd.close()

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
        print '{}:TEST FAILED:{}:{}:{}:{}'.format(operation, fsize, iterations, rnptime, gpgtime)
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
    rnphome = ['--homedir', path.join(WORKDIR, '.rnp')]
    gpghome = ['--homedir', path.join(WORKDIR, '.gnupg')]

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
        #rnpcmd = ' '.join([rnphome, '--encrypt', infile, '--output', rnpout])
        #print rnpcmd
        tmrnp = run_proc_iterative(RNP, rnphome + ['--encrypt', infile, '--output', rnpout], iterations, nooutput = False)
        tmgpg = run_proc_iterative(GPG, gpghome + ['--batch', '--yes', '--trust-model', 'always', '-r', 'performance@rnp', '--compress-level', '0', '--output', gpgout, '--encrypt', infile], iterations, nooutput = False)
        print_test_results(fsize, iterations, tmrnp, tmgpg, 'ENCRYPT')
        #rnpcmd = 'rnp --homedir /tmp/tmpyr3xUT --encrypt /tmp/tmpyr3xUT/smalltest.txt --output=/tmp/tmpyr3xUT/smalltest.txt-rnp-encrypted'
        #gpg2 --homedir /tmp/tmpyr3xUT/.gnupg --batch --yes --trust-model always -r performance@rnp --compress-level 0 --output /tmp/tmpyr3xUT/largetest.txt-gpg-encrypted --encrypt /tmp/tmpyr3xUT/largetest.txt

        # 2. Decryption
        print '\n#2. Decryption\n'
        # 3. Signing
        print '\n#3. Signing\n'
        # 4. Verification
        print '\n#4. Verification\n'
        # 5. Cleartext signing
        print '\n#5. Cleartext signing and verification\n'
        # 6. Detached signature
        print '\n#6. Detached signing and verification\n'

    return

'''
    pubring = '~/.rnp/pubring.gpg'
    secring = '~/.rnp/secring.gpg'
    gpgpub = '~/.gnupg/pubring.gpg'
    gpgsec = '~/.gnupg/secring.gpg'
    renames = []

    for path in [pubring, secring, gpgpub, gpgsec]:
        path = os.path.expanduser(path)
        if os.path.exists(path):
            print 'Found existing keyring at path {}. Renaming it to .old'.format(path)
            os.rename(path, path + '.old')
            renames.append(path + '.old')
        
    try:
        
        pass
    finally:
        print('Renaming back keyrings...')
        for path in renames:
            os.rename(path, path[:-4])
'''

def cleanup():
    shutil.rmtree(WORKDIR)
    return

if __name__ == '__main__':
    setup()
    run_tests()
    #cleanup()