#!/usr/bin/env python

import sys
import tempfile
from os import path
import os
import shutil
import subprocess
from timeit import default_timer as perf_timer
from cli_common import find_utility, run_proc, pswd_pipe, rnp_file_path, random_text, file_text, size_to_readable, raise_err

RNP = ''
RNPK = ''
GPG = ''
WORKDIR = ''
RNPDIR = ''
GPGDIR = ''
RMWORKDIR = False
SMALL_ITERATIONS = 100
LARGE_ITERATIONS = 2
LARGESIZE = 1024*1024*100
SMALLSIZE = 0
SMALLFILE = 'smalltest.txt'
LARGEFILE = 'largetest.txt'
PASSWORD = 'password'

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

def run_iterated(iterations, func, src, dst, *args):
    tstart = perf_timer()
    for i in range(0, iterations):
        func(src, dst, *args)
        os.remove(dst)
    return perf_timer() - tstart

def rnp_symencrypt_file(src, dst, cipher, zlevel = 6, zalgo = 'zip', armour = False):
    pipe = pswd_pipe(PASSWORD)
    params = ['--homedir', RNPDIR, '--pass-fd', str(pipe), '--cipher', cipher, '-z', str(zlevel), '--' + zalgo, '-c', src, '--output', dst]
    if armour:
        params += ['--armor']
    ret, out, err = run_proc(RNP, params)
    os.close(pipe)
    if ret != 0:
        raise_err('rnp symmetric encryption failed', err)

def rnp_decrypt_file(src, dst):
    pipe = pswd_pipe(PASSWORD)
    ret, out, err = run_proc(RNP, ['--homedir', RNPDIR, '--pass-fd', str(pipe), '--decrypt', src, '--output', dst])
    os.close(pipe)
    if ret != 0:
        raise_err('rnp decryption failed', out + err)

def gpg_symencrypt_file(src, dst, cipher = 'AES', zlevel = 6, zalgo = 1, armour = False):
    params = ['--homedir', GPGDIR, '-c', '-z', str(zlevel), '--s2k-count', '524288', '--compress-algo', str(zalgo), '--batch', '--passphrase', PASSWORD, '--cipher-algo', cipher, '--output', dst, src]
    if armour:
        params.insert(2, '--armor')
    ret, out, err = run_proc(GPG, params)
    if ret != 0:
        raise_err('gpg symmetric encryption failed for cipher ' + cipher, err)

def gpg_decrypt_file(src, dst, keypass):
    ret, out, err = run_proc(GPG, ['--homedir', GPGDIR, '--pinentry-mode=loopback', '--batch', '--yes', '--passphrase', keypass, '--trust-model', 'always', '-o', dst, '-d', src])
    if ret != 0:
        raise_err('gpg decryption failed', err)

def print_test_results(fsize, iterations, rnptime, gpgtime, operation):
    if not rnptime or not gpgtime:
        print '{}:TEST FAILED'.format(operation)
        return

    if fsize == SMALLSIZE:
        rnpruns = iterations / rnptime
        gpgruns = iterations / gpgtime
        runstr = '{:.2f} runs/sec vs {:.2f} runs/sec'.format(iterations/rnptime, iterations/gpgtime)

        if rnpruns >= gpgruns:
            percents = (rnpruns - gpgruns) / gpgruns * 100
            print '{:<30}: RNP is {:>3.0f}% FASTER then GnuPG ({})'.format(operation, percents, runstr)
        else:
            percents = (gpgruns - rnpruns) / gpgruns * 100
            print '{:<30}: RNP is {:>3.0f}% SLOWER then GnuPG ({})'.format(operation, percents, runstr)
    else:
        rnpspeed = fsize * iterations / 1024.0 / 1024.0 / rnptime
        gpgspeed = fsize * iterations / 1024.0 / 1024.0 / gpgtime
        spdstr = '{:.2f} MB/sec vs {:.2f} MB/sec'.format(rnpspeed, gpgspeed)

        if rnpspeed >= gpgspeed:
            percents = (rnpspeed - gpgspeed) / gpgspeed * 100
            print '{:<30}: RNP is {:>3.0f}% FASTER then GnuPG ({})'.format(operation, percents, spdstr)
        else:
            percents = (gpgspeed - rnpspeed) / gpgspeed * 100
            print '{:<30}: RNP is {:>3.0f}% SLOWER then GnuPG ({})'.format(operation, percents, spdstr)

    return

def get_file_params(filetype):
    if filetype == 'small':
        infile, outfile, iterations, fsize = (SMALLFILE, SMALLFILE + '.gpg', SMALL_ITERATIONS, SMALLSIZE)
    else:
        infile, outfile, iterations, fsize = (LARGEFILE, LARGEFILE + '.gpg', LARGE_ITERATIONS, LARGESIZE)

    infile = path.join(WORKDIR, infile)
    rnpout = path.join(WORKDIR, outfile + '.rnp')
    gpgout = path.join(WORKDIR, outfile + '.gpg')
    return (infile, rnpout, gpgout, iterations, fsize)

def run_tests():
    rnphome = ['--homedir', RNPDIR]
    gpghome = ['--homedir', GPGDIR]

    # Running each operation iteratively for a small and large file(s), calculating the average
    # 1. Encryption
    print '#1. Small file symmetric encryption'
    infile, rnpout, gpgout, iterations, fsize = get_file_params('small')
    for armour in [False, True]:
        tmrnp = run_iterated(iterations, rnp_symencrypt_file, infile, rnpout, 'AES128', 0, 'zip', armour)
        tmgpg = run_iterated(iterations, gpg_symencrypt_file, infile, gpgout, 'AES128', 0, 1, armour)
        testname = 'ENCRYPT-SMALL-{}'.format('ARMOUR' if armour else 'BINARY')
        print_test_results(fsize, iterations, tmrnp, tmgpg, testname)

    print '#2. Large file symmetric encryption'
    infile, rnpout, gpgout, iterations, fsize = get_file_params('large')
    for cipher in ['AES128', 'AES192', 'AES256', 'TWOFISH', 'BLOWFISH', 'CAST5', 'CAMELLIA128', 'CAMELLIA192', 'CAMELLIA256']:
        tmrnp = run_iterated(iterations, rnp_symencrypt_file, infile, rnpout, cipher, 0, 'zip', False)
        tmgpg = run_iterated(iterations, gpg_symencrypt_file, infile, gpgout, cipher, 0, 1, False)
        testname = 'ENCRYPT-{}-BINARY'.format(cipher)
        print_test_results(fsize, iterations, tmrnp, tmgpg, testname)

    print '#3. Large file armoured encryption'
    tmrnp = run_iterated(iterations, rnp_symencrypt_file, infile, rnpout, 'AES128', 0, 'zip', True)
    tmgpg = run_iterated(iterations, gpg_symencrypt_file, infile, gpgout, 'AES128', 0, 1, True)
    print_test_results(fsize, iterations, tmrnp, tmgpg, 'ENCRYPT-LARGE-ARMOUR')

    print '#4. Small file symmetric decryption'
    infile, rnpout, gpgout, iterations, fsize = get_file_params('small')
    inenc = infile + '.enc'
    for armour in [False, True]:
        gpg_symencrypt_file(infile, inenc, 'AES', 0, 1, armour)
        tmrnp = run_iterated(iterations, rnp_decrypt_file, inenc, rnpout)
        tmgpg = run_iterated(iterations, gpg_decrypt_file, inenc, gpgout, PASSWORD)
        testname = 'DECRYPT-SMALL-{}'.format('ARMOUR' if armour else 'BINARY')
        print_test_results(fsize, iterations, tmrnp, tmgpg, testname)
        os.remove(inenc)

    print '#5. Large file symmetric decryption'
    infile, rnpout, gpgout, iterations, fsize = get_file_params('large')
    inenc = infile + '.enc'
    for cipher in ['AES128', 'AES192', 'AES256', 'TWOFISH', 'BLOWFISH', 'CAST5', 'CAMELLIA128', 'CAMELLIA192', 'CAMELLIA256']:
        gpg_symencrypt_file(infile, inenc, cipher, 0, 1, False)
        tmrnp = run_iterated(iterations, rnp_decrypt_file, inenc, rnpout)
        tmgpg = run_iterated(iterations, gpg_decrypt_file, inenc, gpgout, PASSWORD)
        testname = 'DECRYPT-{}-BINARY'.format(cipher)
        print_test_results(fsize, iterations, tmrnp, tmgpg, testname)
        os.remove(inenc)

    print '#6. Large file armoured decryption'
    gpg_symencrypt_file(infile, inenc, 'AES128', 0, 1, True)
    tmrnp = run_iterated(iterations, rnp_decrypt_file, inenc, rnpout)
    tmgpg = run_iterated(iterations, gpg_decrypt_file, inenc, gpgout, PASSWORD)
    print_test_results(fsize, iterations, tmrnp, tmgpg, 'DECRYPT-LARGE-ARMOUR')
    os.remove(inenc)

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