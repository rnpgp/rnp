#!/usr/bin/env python2

import sys
import distutils.spawn
import tempfile
import getopt
import os
from os import path
import shutil
import subprocess
import re
import random
import string
from subprocess import Popen, PIPE
from cli_common import find_utility, run_proc, pswd_pipe, rnp_file_path, random_text, file_text
import cli_common

WORKDIR = ''
RNP = ''
RNPK = ''
GPG = ''
RNPDIR = ''
PASSWORD = 'password'
RMWORKDIR = False
# Set DEBUG to True to halt on the first error
DEBUG = False
TESTS_SUCCEEDED = []
TESTS_FAILED = []

RE_RSA_KEY = r'(?s)^' \
r'# .*' \
r':public key packet:\s+' \
r'version 4, algo 1, created \d+, expires 0\s+' \
r'pkey\[0\]: \[(\d{4}) bits\]\s+' \
r'pkey\[1\]: \[17 bits\]\s+' \
r'keyid: ([0-9A-F]{16})\s+' \
r'# .*' \
r':user ID packet: "(.+)"\s+' \
r'# .*' \
r':signature packet: algo 1, keyid \2\s+' \
r'.*' \
r'# .*' \
r':public sub key packet:' \
r'.*' \
r':signature packet: algo 1, keyid \2\s+' \
r'.*$'

RE_RSA_KEY_LIST = r'^\s*' \
r'2 keys found\s+' \
r'pub\s+(\d{4})/RSA \(Encrypt or Sign\) ([0-9a-z]{16}) \d{4}-\d{2}-\d{2} \[.*\]\s+' \
r'([0-9a-z]{40})\s+' \
r'uid\s+(.+)\s+' \
r'sub.+\s+' \
r'[0-9a-z]{40}\s+$'

'''
pub   2048/RSA (Encrypt or Sign) 9d11515f507fe5f2 2017-08-14 [SC]
      d496f4b2192cc1af2508203d9d11515f507fe5f2
uid           2048@rnptest
sub   2048/RSA (Encrypt or Sign) ffffaa3655390c6c 2017-08-14 [E]
      b945a8216a8597267ccf5732ffffaa3655390c6c
'''

RE_MULTIPLE_KEY_LIST = r'(?s)^\s*(\d+) (?:key|keys) found.*$'
RE_MULTIPLE_KEY_5 = r'(?s)^\s*' \
r'10 keys found.*' \
r'.+uid\s+0@rnp-multiple' \
r'.+uid\s+1@rnp-multiple' \
r'.+uid\s+2@rnp-multiple' \
r'.+uid\s+3@rnp-multiple' \
r'.+uid\s+4@rnp-multiple.*$'

RE_GPG_SINGLE_RSA_KEY = r'(?s)^\s*' \
r'.+-+\s*' \
r'pub\s+rsa.+' \
r'\s+([0-9A-F]{40})\s*' \
r'uid\s+.+rsakey@gpg.*'

RE_GPG_GOOD_SIGNATURE = r'(?s)^\s*' \
r'gpg: Signature made .*' \
r'gpg: Good signature from "(.*)".*'

RE_RNP_GOOD_SIGNATURE = r'(?s)^.*' \
r'Good signature for .* made .*' \
r'using .* key .*' \
r'signature .*' \
r'uid\s+(.*)\s*$'

def setup():
    # Setting up directories.
    global RMWORKDIR, WORKDIR, RNPDIR, RNP, RNPK, GPG, GPGDIR
    WORKDIR = os.getcwd()
    if not '/tmp/' in WORKDIR:
        WORKDIR = tempfile.mkdtemp()
        RMWORKDIR = True

    print 'Running in ' + WORKDIR

    RNPDIR = path.join(WORKDIR, '.rnp')
    RNP = rnp_file_path('src/rnp/rnp')
    RNPK = rnp_file_path('src/rnpkeys/rnpkeys')
    os.mkdir(RNPDIR, 0700)

    GPGDIR = path.join(WORKDIR, '.gpg')
    GPG = find_utility('gpg2', False)
    if not GPG:
        GPG = find_utility('gpg')

    os.mkdir(GPGDIR, 0700)

    return

def check_packets(fname, regexp):
    ret, output, err = run_proc(GPG, ['--list-packets', fname])
    if ret != 0:
        print err
        return None
    else:
        result = re.match(regexp, output)
        if not result and DEBUG:
            print 'Wrong packets: \n' + output
        return result

def clear_keyrings():
    shutil.rmtree(RNPDIR)
    shutil.rmtree(GPGDIR)
    os.mkdir(RNPDIR, 0700)
    os.mkdir(GPGDIR, 0700)

def compare_files(src, dst, message):
    if file_text(src) != file_text(dst):
        raise_err(message)

def remove_files(*args):
    try:
        for fpath in args:
            os.remove(fpath)
    except:
        pass

def raise_err(msg, log = None):
    if log and DEBUG:
        print log
    raise NameError(msg)

def run_test(func, *args):
    global TESTS_SUCCEEDED, TESTS_FAILED
    name = '{}({})'.format(func.__name__, ', '.join(map(str, args)))
    try:
        func(*args)
        print 'SUCCESS : ' + name
        TESTS_SUCCEEDED += [name]
    except Exception as e:
        TESTS_FAILED += [name]
        if DEBUG:
            raise
        else:
            print 'FAILURE : {}'.format(name)

def rnpkey_generate_rsa(bits = None, cleanup = True):
    # Setup command line params
    if bits: 
        params = ['--numbits', str(bits)]
    else:
        params = []
        bits = 2048

    userid = str(bits) + '@rnptest'
    # Open pipe for password
    pipe = pswd_pipe(PASSWORD) 
    params = params + ['--homedir', RNPDIR, '--pass-fd', str(pipe), '--userid', userid, '--generate-key']
    # Run key generation
    ret, out, err = run_proc(RNPK, params)
    os.close(pipe)
    if ret != 0: raise_err('key generation failed', err)
    # Check packets using the gpg
    match = check_packets(path.join(RNPDIR, 'pubring.gpg'), RE_RSA_KEY)
    if not match : raise_err('generated key check failed')
    keybits = int(match.group(1))
    if keybits > bits or keybits <= bits - 8 : raise_err('wrong key bits')
    keyid = match.group(2)
    if not match.group(3) == userid: raise_err('wrong user id')
    # List keys using the rnpkeys
    ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
    if ret != 0: raise_err('key list failed', err)
    match = re.match(RE_RSA_KEY_LIST, out)
    # Compare key ids
    if not match: raise_err('wrong key list output', out)
    if not match.group(3)[-16:] == match.group(2) or not match.group(2) == keyid.lower():
        raise_err('wrong key ids')
    if not match.group(1) == str(bits):
        raise_err('wrong key bits in list')
    # Import key to the gnupg
    ret, out, err = run_proc(GPG, ['--batch', '--passphrase', PASSWORD, '--homedir', GPGDIR, '--import', path.join(RNPDIR, 'pubring.gpg'), path.join(RNPDIR, 'secring.gpg')])
    if ret != 0: raise_err('gpg key import failed', err)
    # Cleanup and return
    if cleanup: 
        clear_keyrings()
        return None
    else:
        return keyid

def rnpkey_generate_multiple():
    # Generate 5 keys with different user ids
    for i in range(0, 5):
        # generate the next key
        pipe = pswd_pipe(PASSWORD)
        userid = str(i) + '@rnp-multiple'
        ret, out, err = run_proc(RNPK, ['--numbits', '2048', '--homedir', RNPDIR, '--pass-fd', str(pipe), '--userid', userid, '--generate-key'])
        os.close(pipe)
        if ret != 0: raise_err('key generation failed', err)
        # list keys using the rnpkeys, checking whether it reports correct key number
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
        if ret != 0: raise_err('key list failed', err)
        match = re.match(RE_MULTIPLE_KEY_LIST, out)
        if not match: raise_err('wrong key list output', out)
        if not match.group(1) == str((i + 1) * 2):
            raise_err('wrong key count', out)

    # Checking the 5 keys output
    ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
    if ret != 0: raise_err('key list failed', err)
    match = re.match(RE_MULTIPLE_KEY_5, out)
    if not match: 
        raise_err('wrong key list output', out)

    # Cleanup and return
    clear_keyrings()
    return

def rnpkey_import_from_gpg(cleanup = True):
    # Generate key in GnuPG
    ret, out, err = run_proc(GPG, ['--batch', '--homedir', GPGDIR, '--passphrase', '', '--quick-generate-key', 'rsakey@gpg', 'rsa'])
    if ret != 0: raise_err('gpg key generation failed', err)
    # Getting fingerprint of the generated key
    ret, out, err = run_proc(GPG, ['--batch', '--homedir', GPGDIR, '--list-keys'])
    match = re.match(RE_GPG_SINGLE_RSA_KEY, out)
    if not match: raise_err('wrong gpg key list output', out)
    keyfp = match.group(1)
    # Exporting generated public key
    ret, out, err = run_proc(GPG, ['--batch', '--homedir', GPGDIR, '--armour', '--export', keyfp])
    if ret != 0: raise_err('gpg : public key export failed', err)
    pubpath = path.join(RNPDIR, keyfp + '-pub.asc')
    with open(pubpath, 'w+') as f:
        f.write(out)
    # Exporting generated secret key
    ret, out, err = run_proc(GPG, ['--batch', '--homedir', GPGDIR, '--armour', '--export-secret-key', keyfp])
    if ret != 0: raise_err('gpg : secret key export failed', err)
    secpath = path.join(RNPDIR, keyfp + '-sec.asc')
    with open(secpath, 'w+') as f:
        f.write(out)
    # Importing public key to rnp
    ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--import-key', pubpath])
    if ret != 0: raise_err('rnp : public key import failed', err)
    # Importing secret key to rnp
    ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--import-key', secpath])
    if ret != 0: raise_err('rnp : secret key import failed', err)
    # We do not check keyrings after the import - imported by RNP keys are not saved yet

    if cleanup:
        clear_keyrings()

def rnpkey_export_to_gpg(cleanup = True):
    # Open pipe for password
    pipe = pswd_pipe(PASSWORD) 
    # Run key generation
    ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--pass-fd', str(pipe), '--userid', 'rsakey@rnp', '--generate-key'])
    os.close(pipe)
    if ret != 0: raise_err('key generation failed', err)
    # Export key
    ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--export-key', 'rsakey@rnp'])
    if ret != 0: raise_err('key export failed', err)
    pubpath = path.join(RNPDIR, 'rnpkey-pub.asc')
    with open(pubpath, 'w+') as f:
        f.write(out)
    # Import key with GPG
    ret, out, err = run_proc(GPG, ['--batch', '--homedir', GPGDIR, '--import', pubpath])
    if ret != 0: raise_err('gpg : public key import failed', err)

    if cleanup: clear_keyrings()

def rnp_genkey_rsa(userid, bits = 2048):
    pipe = pswd_pipe(PASSWORD)
    ret, out, err = run_proc(RNPK, ['--numbits', str(bits), '--homedir', RNPDIR, '--pass-fd', str(pipe), '--userid', userid, '--generate-key'])
    os.close(pipe)
    if ret != 0:
        raise_err('rsa key generation failed', err)

def rnp_encrypt_file(recipient, src, dst):
    ret, out, err = run_proc(RNP, ['--homedir', RNPDIR, '--userid', recipient, '--encrypt', src, '--output', dst])
    if ret != 0: 
        raise_err('rnp encryption failed', err)

def rnp_decrypt_file(src, dst):
    pipe = pswd_pipe(PASSWORD)
    ret, out, err = run_proc(RNP, ['--homedir', RNPDIR, '--pass-fd', str(pipe), '--decrypt', src, '--output', dst])
    os.close(pipe)
    if ret != 0: 
        raise_err('rnp decryption failed', out + err)

def rnp_sign_file(src, dst, signer, armour = False):
    pipe = pswd_pipe(PASSWORD)
    params = ['--homedir', RNPDIR, '--pass-fd', str(pipe), '--userid', signer, '--sign', src, '--output', dst]
    if armour:
        params += ['--armor']
    ret, out, err = run_proc(RNP, params)
    os.close(pipe)
    if ret != 0: 
        raise_err('rnp signing failed', err)

def rnp_sign_detached(src, signer):
    pipe = pswd_pipe(PASSWORD)
    ret, out, err = run_proc(RNP, ['--homedir', RNPDIR, '--pass-fd', str(pipe), '--userid', signer, '--sign', '--detach', src])
    os.close(pipe)
    if ret != 0: 
        raise_err('rnp detached signing failed', err)

def rnp_verify_file(src, dst, signer = None):
    params = ['--homedir', RNPDIR, '--verify-cat', src, '--output', dst]
    ret, out, err = run_proc(RNP, params)
    if ret != 0: 
        raise_err('rnp verification failed', err + out)
    # Check RNP output
    match = re.match(RE_RNP_GOOD_SIGNATURE, err)
    if not match: 
        raise_err('wrong rnp verification output', err)
    if signer and (not match.group(1).strip() == signer.strip()):
        raise_err('rnp verification failed, wrong signer')

def rnp_verify_detached(sig, signer = None):
    ret, out, err = run_proc(RNP, ['--homedir', RNPDIR, '--verify', sig])
    if ret != 0: 
        raise_err('rnp detached verification failed', err + out)
    # Check RNP output
    match = re.match(RE_RNP_GOOD_SIGNATURE, err)
    if not match: 
        raise_err('wrong rnp detached verification output', err)
    if signer and (not match.group(1).strip() == signer.strip()):
        raise_err('rnp detached verification failed, wrong signer')

def gpg_import_pubring(kpath = None):
    if not kpath:
        kpath = path.join(RNPDIR, 'pubring.gpg')
    ret, out, err = run_proc(GPG, ['--batch', '--homedir', GPGDIR, '--import', kpath])
    if ret != 0: 
        raise_err('gpg key import failed', err)

def gpg_import_secring(kpath = None):
    if not kpath:
        kpath = path.join(RNPDIR, 'secring.gpg')
    ret, out, err = run_proc(GPG, ['--batch', '--passphrase', PASSWORD, '--homedir', GPGDIR, '--import', kpath])
    if ret != 0: 
        raise_err('gpg secret key import failed', err)

def gpg_encrypt_file(src, dst, cipher = 'AES', zlevel = 6):
    ret, out, err = run_proc(GPG, ['--homedir', GPGDIR, '-e', '-z', str(zlevel), '-r', 'encryption@rnp', '--batch', '--cipher-algo', cipher, '--trust-model', 'always', '--output', dst, src])
    if ret != 0: 
        raise_err('gpg encryption failed for cipher ' + cipher, err)

def gpg_decrypt_file(src, dst, keypass):
    ret, out, err = run_proc(GPG, ['--homedir', GPGDIR, '--pinentry-mode=loopback', '--batch', '--yes', '--passphrase', keypass, '--trust-model', 'always', '-o', dst, '-d', src])
    if ret != 0: 
        raise_err('gpg decryption failed', err)

def gpg_verify_file(src, dst, signer = None):
    ret, out, err = run_proc(GPG, ['--homedir', GPGDIR, '--batch', '--yes', '--trust-model', 'always', '-o', dst, '--verify', src])
    if ret != 0: 
        raise_err('gpg verification failed', err)
    # Check GPG output
    match = re.match(RE_GPG_GOOD_SIGNATURE, err)
    if not match: 
        raise_err('wrong gpg verification output', err)
    if signer and (not match.group(1) == signer):
        raise_err('gpg verification failed, wrong signer')

def gpg_verify_detached(src, sig, signer = None):
    ret, out, err = run_proc(GPG, ['--homedir', GPGDIR, '--batch', '--yes', '--trust-model', 'always', '--verify', sig, src])
    if ret != 0: 
        raise_err('gpg detached verification failed', err)
    # Check GPG output
    match = re.match(RE_GPG_GOOD_SIGNATURE, err)
    if not match: 
        raise_err('wrong gpg detached verification output', err)
    if signer and (not match.group(1) == signer):
        raise_err('gpg detached verification failed, wrong signer')

def gpg_sign_file(src, dst, signer):
    ret, out, err = run_proc(GPG, ['--homedir', GPGDIR, '--pinentry-mode=loopback', '--batch', '--yes', '--passphrase', PASSWORD, '--trust-model', 'always', '-u', signer, '-o', dst, '-s', src])
    if ret != 0: 
        raise_err('gpg signing failed', err)

def gpg_sign_detached(src, signer):
    ret, out, err = run_proc(GPG, ['--homedir', GPGDIR, '--pinentry-mode=loopback', '--batch', '--yes', '--passphrase', PASSWORD, '--trust-model', 'always', '-u', signer, '--detach-sign', src])
    if ret != 0: 
        raise_err('gpg detached signing failed', err)

'''
    Things to try here later on:
    - different symmetric algorithms
    - different file sizes (block len/packet len tests)
    - different public key algorithms
    - different compression levels/algorithms
'''

def rnp_encryption_gpg_to_rnp(cipher, filesize, zlevel = 6):
    src, dst, dec = map(lambda x: path.join(WORKDIR, 'cleartext' + x), ['.txt', '.gpg', '.rnp'])
    try:
        # Generate random file of required size
        random_text(src, filesize)
        # Encrypt cleartext file with GPG
        gpg_encrypt_file(src, dst, cipher, zlevel)
        # Decrypt encrypted file with RNP
        rnp_decrypt_file(dst, dec)
        compare_files(src, dec, 'rnp decrypted data differs')
    finally:
        # Cleanup
        remove_files(src, dst, dec)

def rnp_encryption_rnp_to_gpg(filesize):
    src, dst, enc = map(lambda x: path.join(WORKDIR, 'cleartext' + x), ['.txt', '.gpg', '.rnp'])
    try:
        # Generate random file of required size
        random_text(src, filesize)
        # Encrypt cleartext file with RNP
        rnp_encrypt_file('encryption@rnp', src, enc)
        # Decrypt encrypted file with GPG
        gpg_decrypt_file(enc, dst, PASSWORD)
        compare_files(src, dst, 'gpg decrypted data differs')
        # Decrypt encrypted file with RNP
        rnp_decrypt_file(enc, dst)
        compare_files(src, dst, 'rnp decrypted data differs')
    finally:
        # Cleanup
        remove_files(src, dst, enc)

    return

'''
    Things to try later:
    - different public key algorithms
    - decryption with generated by GPG and imported keys
'''

def rnp_encryption():
    # Generate keypair in RNP
    rnp_genkey_rsa('encryption@rnp')
    # Add some other keys to the keyring
    rnp_genkey_rsa('dummy1@rnp', 1024)
    rnp_genkey_rsa('dummy2@rnp', 1024)
    # Import keyring to the GPG
    gpg_import_pubring()
    # Encrypt cleartext file with GPG and decrypt it with RNP, using different ciphers and file sizes
    # Could be non working, see #353: IDEA, 3DES, CAST5, BLOWFISH
    ciphers = ['AES', 'AES192', 'AES256', 'TWOFISH', 'CAMELLIA128', 'CAMELLIA192', 'CAMELLIA256', 'IDEA', '3DES', 'CAST5', 'BLOWFISH']
    #ciphers = ['AES', 'AES192', 'AES256', 'TWOFISH', 'CAMELLIA128', 'CAMELLIA192', 'CAMELLIA256']
    sizes = [20, 1000, 2000, 5000, 10000, 20000, 60000, 1000000]
    for cipher in ciphers:
        for size in sizes:
            run_test(rnp_encryption_gpg_to_rnp, cipher, size)
    
    # Tests for compression level
    for zlevel in range(0, 10):
        run_test(rnp_encryption_gpg_to_rnp, 'AES', 500000, zlevel)
    # Import secret keyring to GPG
    gpg_import_secring()
    # Encrypt cleartext with RNP and decrypt with GPG
    for size in sizes:
        run_test(rnp_encryption_rnp_to_gpg, size)
    # Cleanup
    clear_keyrings()
    return

def rnp_signing_rnp_to_gpg(filesize):
    src, sig, asc, ver = map(lambda x: path.join(WORKDIR, 'cleartext' + x), ['.txt', '.sig', '.asc', '.ver'])
    try:
        # Generate random file of required size
        random_text(src, filesize)
        # Sign file with RNP
        rnp_sign_file(src, sig, 'signing@rnp')
        # Verify signed file with RNP
        rnp_verify_file(sig, ver, 'signing@rnp')
        compare_files(src, ver, 'rnp verified data differs')
        remove_files(ver)
        # Verify signed message with GPG
        gpg_verify_file(sig, ver, 'signing@rnp')
        compare_files(src, ver, 'gpg verified data differs')
        remove_files(ver)
        # Armored signing test
        rnp_sign_file(src, asc, 'signing@rnp', armour = True)
        # Verify signed file with RNP
        rnp_verify_file(asc, ver, 'signing@rnp')
        compare_files(src, ver, 'rnp verified data differs')
        remove_files(ver)
        # Verify signed message with GPG
        gpg_verify_file(asc, ver, 'signing@rnp')
        compare_files(src, ver, 'gpg verified data differs')
        remove_files(ver)
    finally:
        # Cleanup
        remove_files(src, sig, asc, ver)

    return

def rnp_detached_signing_rnp_to_gpg(filesize):
    src, sig = map(lambda x: path.join(WORKDIR, 'cleartext' + x), ['.txt', '.txt.sig'])
    try:
        # Generate random file of required size
        random_text(src, filesize)
        # Sign file with RNP
        rnp_sign_detached(src, 'signing@rnp')
        # Verify signature with RNP
        rnp_verify_detached(sig, 'signing@rnp')
        # Verify signed message with GPG
        gpg_verify_detached(src, sig, 'signing@rnp')
    finally:
        # Cleanup
        remove_files(src, sig)

    return

def rnp_signing_gpg_to_rnp(filesize):
    src, sig, ver = map(lambda x: path.join(WORKDIR, 'cleartext' + x), ['.txt', '.sig', '.ver'])
    try:
        # Generate random file of required size
        random_text(src, filesize)
        # Sign file with GPG
        gpg_sign_file(src, sig, 'signing@gpg')
        # Verify file with RNP
        rnp_verify_file(sig, ver, 'signing@gpg')
        compare_files(src, ver, 'rnp verified data differs')
    finally:
        # Cleanup
        remove_files(src, sig, ver)
    
    return

def rnp_detached_signing_gpg_to_rnp(filesize):
    src, sig = map(lambda x: path.join(WORKDIR, 'cleartext' + x), ['.txt', '.txt.sig'])
    try:
        # Generate random file of required size
        random_text(src, filesize)
        # Sign file with GPG
        gpg_sign_detached(src, 'signing@gpg')
        # Verify file with RNP
        rnp_verify_detached(sig, 'signing@gpg')
    finally:
        # Cleanup
        remove_files(src, sig)
    
    return

'''
    Things to try later:
    - different public key algorithms
    - different hash algorithms where applicable
    - cleartext signing/verification
    - detached signing/verification
'''
def rnp_signing():
    # Generate keypair in RNP
    rnp_genkey_rsa('signing@rnp')
    # Add some other keys to the keyring
    rnp_genkey_rsa('dummy1@rnp', 1024)
    rnp_genkey_rsa('dummy2@rnp', 1024)
    # Import keyring to the GPG
    gpg_import_pubring()
    sizes = [20, 1000, 2000, 5000, 10000, 20000, 60000, 1000000]
    for size in sizes:
        run_test(rnp_signing_rnp_to_gpg, size)
        run_test(rnp_detached_signing_rnp_to_gpg, size)
    # Generate additional keypair in RNP
    rnp_genkey_rsa('signing@gpg')
    # Import secret keyring to the GPG
    gpg_import_secring()
    for size in sizes:
        run_test(rnp_signing_gpg_to_rnp, size)
        run_test(rnp_detached_signing_gpg_to_rnp, size)

    return

def run_rnp_tests():
    # 1. Encryption / decryption against GPG
    rnp_encryption()
    # 2. Signing / verification against GPG
    rnp_signing()
    
    return

'''
    Things to try here later on:
    - different public key algorithms
    - different key protection levels/algorithms
    - armoured import/export
'''
def run_rnpkeys_tests():
    # 1. Generate default RSA key
    run_test(rnpkey_generate_rsa)
    # 2. Generate 4096-bit RSA key
    run_test(rnpkey_generate_rsa, 4096)
    # 3. Generate multiple RSA keys and check if they are all available
    run_test(rnpkey_generate_multiple)
    # 4. Generate key with GnuPG and import it to rnp
    run_test(rnpkey_import_from_gpg)
    # 5. Generate key with RNP and export it and then import to GnuPG
    run_test(rnpkey_export_to_gpg)

    return

def run_tests():
    global DEBUG

    # Parsing command line parameters
    try:
        opts, args = getopt.getopt(sys.argv, 'hd', ['help', 'debug'])
    except getopt.GetoptError:
        print "Wrong usage. Run cli_tests --help"
        sys.exit(2)

    tests = []

    for arg in args[1:]:
        if arg in ['-h', '--help']:
            print 'Usage:\ncli_tests [-h | --help] [rnp] [rnpkeys] [all] [-d | --debug]'
            sys.exit(0)
        elif arg in ['-d', '--debug']:
            DEBUG = True
            cli_common.DEBUG = True
        elif arg == 'all':
            tests += ['rnp', 'rnpkeys']
        elif arg in ['rnp', 'rnpkeys']:
            tests += [arg]
        else:
            print 'Wrong parameter: {}. Run cli_tests -h for help.'.format(arg)
            sys.exit(2)

    if len(tests) == 0:
        print 'You must specify at least one test group to run. See cli_tests -h for help.'
        sys.exit(2)

    # Parameters are ok so we can proceed
    setup()

    if 'rnpkeys' in tests:
        run_rnpkeys_tests()
    if 'rnp' in tests:
        run_rnp_tests()

    succeeded = len(TESTS_SUCCEEDED)
    failed = len(TESTS_FAILED)
    print '\nRun {} tests, {} succeeded and {} failed.\n'.format(succeeded + failed, succeeded, failed)
    if failed > 0:
        print 'Failed tests:\n' + '\n'.join(TESTS_FAILED)
        sys.exit(1)

def cleanup():
    if DEBUG:
        return

    try:
        if RMWORKDIR:
            shutil.rmtree(WORKDIR)
        else:
            shutil.rmtree(RNPDIR)
            shutil.rmtree(GPGDIR)
    except:
        pass

    return

if __name__ == '__main__':
    try:
        run_tests()
    finally:
        cleanup()
