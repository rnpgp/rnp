#!/usr/bin/env python2

import sys
import tempfile
import os
from os import path
import shutil
import re
import time
import unittest
import itertools
import logging

from cli_common import (
    find_utility,
    run_proc,
    pswd_pipe,
    rnp_file_path,
    random_text,
    file_text,
    raise_err,
    list_upto
)
from gnupg import GnuPG as GnuPG
from rnp import Rnp as Rnp

WORKDIR = ''
RNP = ''
RNPK = ''
GPG = ''
GPGCONF = ''
RNPDIR = ''
PASSWORD = 'password'
RMWORKDIR = True
TESTS_SUCCEEDED = []
TESTS_FAILED = []
TEST_WORKFILES = []


# Key userids
KEY_ENCRYPT = 'encryption@rnp'
KEY_SIGN_RNP = 'signing@rnp'
KEY_SIGN_GPG = 'signing@gpg'

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

RE_GPG_GOOD_SIGNATURE = r'(?s)^.*' \
r'gpg: Signature made .*' \
r'gpg: Good signature from "(.*)".*'

RE_RNP_GOOD_SIGNATURE = r'(?s)^.*' \
r'Good signature made .*' \
r'using .* key .*' \
r'pub .*' \
r'uid\s+(.*)\s*' \
r'Signature\(s\) verified successfully.*$'

RNP_TO_GPG_ZALGS = { 'zip' : '1', 'zlib' : '2', 'bzip2' : '3' }
# These are mostly identical
RNP_TO_GPG_CIPHERS = {'AES' : 'aes128', 'AES192' : 'aes192', 'AES256' : 'aes256', 'TWOFISH' : 'twofish',
        'CAMELLIA128' : 'camellia128', 'CAMELLIA192' : 'camellia192', 'CAMELLIA256' : 'camellia256',
        'IDEA' : 'idea', '3DES' : '3des', 'CAST5' : 'cast5', 'BLOWFISH' : 'blowfish'}

def check_packets(fname, regexp):
    ret, output, err = run_proc(GPG, ['--list-packets', fname])
    if ret != 0:
        logging.error(err)
        return None
    else:
        result = re.match(regexp, output)
        if not result:
            logging.debug('Wrong packets:')
            logging.debug(output)
        return result


def clear_keyrings():
    shutil.rmtree(RNPDIR, ignore_errors=True)
    os.mkdir(RNPDIR, 0700)

    run_proc(GPGCONF, ['--homedir', GPGDIR, '--kill', 'gpg-agent'])
    while os.path.isdir(GPGDIR):
        try:
            shutil.rmtree(GPGDIR)
        except:
            time.sleep(0.1)
    os.mkdir(GPGDIR, 0700)

def compare_files(src, dst, message):
    if file_text(src) != file_text(dst):
        raise_err(message)

def compare_file(src, string, message):
    if file_text(src) != string:
        raise_err(message)

def compare_file_ex(src, string, message, symbol='?'):
    ftext = file_text(src)
    if len(ftext) != len(string):
        raise_err(message)
    for i in range(0, len(ftext)):
        if (ftext[i] != symbol[0]) and (ftext[i] != string[i]):
            raise_err(message)

def remove_files(*args):
    try:
        for fpath in args:
            os.remove(fpath)
    except:
        pass

def reg_workfiles(mainname, *exts):
    global TEST_WORKFILES
    res = []
    for ext in exts:
        fpath = path.join(WORKDIR, mainname + ext)
        if fpath in TEST_WORKFILES:
            logging.warn('Warning! Path {} is already in TEST_WORKFILES'.format(fpath))
        else:
            TEST_WORKFILES += [fpath]
        res += [fpath]
    return res


def clear_workfiles():
    global TEST_WORKFILES
    for fpath in TEST_WORKFILES:
        try:
            os.remove(fpath)
        except OSError:
            pass
    TEST_WORKFILES = []


def rnp_genkey_rsa(userid, bits=2048, pswd=PASSWORD):
    pipe = pswd_pipe(pswd)
    ret, _, err = run_proc(RNPK, ['--numbits', str(bits), '--homedir',
                                    RNPDIR, '--pass-fd', str(pipe), '--userid', userid, '--generate-key'])
    os.close(pipe)
    if ret != 0:
        raise_err('rsa key generation failed', err)


def rnp_params_insert_z(params, pos, z):
    if z:
        if len(z) > 0 and z[0] != None:
            params[pos:pos] = ['--' + z[0]]
        if len(z) > 1 and z[1] != None:
            params[pos:pos] = ['-z', str(z[1])]

def rnp_params_insert_aead(params, pos, aead):
    if aead != None:
        params[pos:pos] = ['--aead=' + aead[0]] if len(aead) > 0 and aead[0] != None else ['--aead']
        if len(aead) > 1 and aead[1] != None:
            params[pos + 1:pos + 1] = ['--aead-chunk-bits=' + str(aead[1])]

def rnp_encrypt_file_ex(src, dst, recipients=None, passwords=None, aead=None, cipher=None, z=None, armor=False):
    params = ['--homedir', RNPDIR, src, '--output', dst]
    # Recipients. None disables PK encryption, [] to use default key. Otheriwse list of ids.
    if recipients != None:
        params[2:2] = ['--encrypt']
        for userid in reversed(recipients):
            params[2:2] = ['-r', userid]
    # Passwords to encrypt to. None or [] disables password encryption.
    if passwords:
        if recipients == None:
            params[2:2] = ['-c']
        pipe = pswd_pipe('\n'.join(passwords))
        params[2:2] = ['--pass-fd', str(pipe)]
        params[2:2] = ['--passwords', str(len(passwords))]

    # Cipher or None for default
    if cipher: params[2:2] = ['--cipher', cipher]
    # Armor
    if armor: params += ['--armor']
    rnp_params_insert_aead(params, 2, aead)
    rnp_params_insert_z(params, 2, z)
    ret, _, err = run_proc(RNP, params)
    if passwords: os.close(pipe)
    if ret != 0:
        raise_err('rnp encryption failed', err)

def rnp_encrypt_and_sign_file(src, dst, recipients, encrpswd, signers, signpswd, aead=None, cipher=None, z=None, armor=False):
    params = ['--homedir', RNPDIR, '--sign', '--encrypt', src, '--output', dst]
    pipe = pswd_pipe('\n'.join(encrpswd + signpswd))
    params[2:2] = ['--pass-fd', str(pipe)]

    # Encrypting passwords if any
    if encrpswd:
        params[2:2] = ['--passwords', str(len(encrpswd))]
    # Adding recipients. If list is empty then default will be used.
    for userid in reversed(recipients):
        params[2:2] = ['-r', userid]
    # Adding signers. If list is empty then default will be used.
    for signer in reversed(signers):
        params[2:2] = ['-u', signer]
    # Cipher or None for default
    if cipher: params[2:2] = ['--cipher', cipher]
    # Armor
    if armor: params += ['--armor']
    rnp_params_insert_aead(params, 2, aead)
    rnp_params_insert_z(params, 2, z)

    ret, _, err = run_proc(RNP, params)
    os.close(pipe)
    if ret != 0:
        raise_err('rnp encrypt-and-sign failed', err)

def rnp_decrypt_file(src, dst, password = PASSWORD):
    pipe = pswd_pipe(password)
    ret, out, err = run_proc(
        RNP, ['--homedir', RNPDIR, '--pass-fd', str(pipe), '--decrypt', src, '--output', dst])
    os.close(pipe)
    if ret != 0:
        raise_err('rnp decryption failed', out + err)

def rnp_sign_file_ex(src, dst, signers, passwords, options = None):
    pipe = pswd_pipe('\n'.join(passwords))
    params = ['--homedir', RNPDIR, '--pass-fd', str(pipe), src]
    if dst: params += ['--output', dst]
    if 'cleartext' in options:
        params[4:4] = ['--clearsign']
    else:
        params[4:4] = ['--sign']
        if 'armor' in options: params += ['--armor']
        if 'detached' in options: params += ['--detach']

    for signer in reversed(signers):
        params[4:4] = ['--userid', signer]

    ret, _, err = run_proc(RNP, params)
    os.close(pipe)
    if ret != 0:
        raise_err('rnp signing failed', err)


def rnp_sign_file(src, dst, signers, passwords, armor=False):
    options = []
    if armor: options += ['armor']
    rnp_sign_file_ex(src, dst, signers, passwords, options)


def rnp_sign_detached(src, signers, passwords, armor=False):
    options = ['detached']
    if armor: options += ['armor']
    rnp_sign_file_ex(src, None, signers, passwords, options)


def rnp_sign_cleartext(src, dst, signers, passwords):
    rnp_sign_file_ex(src, dst, signers, passwords, ['cleartext'])


def rnp_verify_file(src, dst, signer=None):
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


def rnp_verify_detached(sig, signer=None):
    ret, out, err = run_proc(RNP, ['--homedir', RNPDIR, '--verify', sig])
    if ret != 0:
        raise_err('rnp detached verification failed', err + out)
    # Check RNP output
    match = re.match(RE_RNP_GOOD_SIGNATURE, err)
    if not match:
        raise_err('wrong rnp detached verification output', err)
    if signer and (not match.group(1).strip() == signer.strip()):
        raise_err('rnp detached verification failed, wrong signer'.format())


def rnp_verify_cleartext(src, signer=None):
    params = ['--homedir', RNPDIR, '--verify', src]
    ret, out, err = run_proc(RNP, params)
    if ret != 0:
        raise_err('rnp verification failed', err + out)
    # Check RNP output
    match = re.match(RE_RNP_GOOD_SIGNATURE, err)
    if not match:
        raise_err('wrong rnp verification output', err)
    if signer and (not match.group(1).strip() == signer.strip()):
        raise_err('rnp verification failed, wrong signer')


def gpg_import_pubring(kpath=None):
    if not kpath:
        kpath = path.join(RNPDIR, 'pubring.gpg')
    ret, _, err = run_proc(
        GPG, ['--batch', '--homedir', GPGDIR, '--import', kpath])
    if ret != 0:
        raise_err('gpg key import failed', err)


def gpg_import_secring(kpath=None, password = PASSWORD):
    if not kpath:
        kpath = path.join(RNPDIR, 'secring.gpg')
    ret, _, err = run_proc(
        GPG, ['--batch', '--passphrase', password, '--homedir', GPGDIR, '--import', kpath])
    if ret != 0:
        raise_err('gpg secret key import failed', err)


def gpg_export_secret_key(userid, password, keyfile):
    ret, _, err = run_proc(GPG, ['--batch', '--homedir', GPGDIR, '--pinentry-mode=loopback', '--yes',
        '--passphrase', password, '--output', keyfile, '--export-secret-key', userid])

    if ret != 0:
        raise_err('gpg secret key export failed', err)

def gpg_params_insert_z(params, pos, z):
    if z:
        if len(z) > 0 and z[0] != None:
            params[pos:pos] = ['--compress-algo', RNP_TO_GPG_ZALGS[z[0]]]
        if len(z) > 1 and z[1] != None:
            params[pos:pos] = ['-z', str(z[1])]

def gpg_encrypt_file(src, dst, cipher=None, z=None, armor=False):
    params = ['--homedir', GPGDIR, '-e', '-r', KEY_ENCRYPT, '--batch', '--trust-model', 'always', '--output', dst, src]
    if z: gpg_params_insert_z(params, 3, z)
    if cipher: params[3:3] = ['--cipher-algo', RNP_TO_GPG_CIPHERS[cipher]]
    if armor: params[2:2] = ['--armor']

    ret, out, err = run_proc(GPG, params)
    if ret != 0:
        raise_err('gpg encryption failed for cipher ' + cipher, err)


def gpg_symencrypt_file(src, dst, cipher=None, z=None, armor=False, aead=None):
    params = ['--homedir', GPGDIR, '-c', '--s2k-count', '65536', '--batch', '--passphrase', PASSWORD, '--output', dst, src]
    if z: gpg_params_insert_z(params, 3, z)
    if cipher: params[3:3] = ['--cipher-algo', RNP_TO_GPG_CIPHERS[cipher]]
    if armor: params[2:2] = ['--armor']
    if aead != None:
        if len(aead) > 0 and aead[0] != None:
            params[3:3] = ['--aead-algo', aead[0]]
        if len(aead) > 1 and aead[1] != None:
            params[3:3] = ['--chunk-size', str(aead[1] + 6)]
        params[3:3] = ['--rfc4880bis', '--force-aead']

    ret, out, err = run_proc(GPG, params)
    if ret != 0:
        raise_err('gpg symmetric encryption failed for cipher ' + cipher, err)


def gpg_decrypt_file(src, dst, keypass):
    ret, out, err = run_proc(GPG, ['--homedir', GPGDIR, '--pinentry-mode=loopback', '--batch',
                                   '--yes', '--passphrase', keypass, '--trust-model', 'always', '-o', dst, '-d', src])
    if ret != 0:
        raise_err('gpg decryption failed', err)


def gpg_verify_file(src, dst, signer=None):
    ret, out, err = run_proc(GPG, ['--homedir', GPGDIR, '--batch',
                                   '--yes', '--trust-model', 'always', '-o', dst, '--verify', src])
    if ret != 0:
        raise_err('gpg verification failed', err)
    # Check GPG output
    match = re.match(RE_GPG_GOOD_SIGNATURE, err)
    if not match:
        raise_err('wrong gpg verification output', err)
    if signer and (not match.group(1) == signer):
        raise_err('gpg verification failed, wrong signer')


def gpg_verify_detached(src, sig, signer=None):
    ret, _, err = run_proc(GPG, ['--homedir', GPGDIR, '--batch',
                                   '--yes', '--trust-model', 'always', '--verify', sig, src])
    if ret != 0:
        raise_err('gpg detached verification failed', err)
    # Check GPG output
    match = re.match(RE_GPG_GOOD_SIGNATURE, err)
    if not match:
        raise_err('wrong gpg detached verification output', err)
    if signer and (not match.group(1) == signer):
        raise_err('gpg detached verification failed, wrong signer')


def gpg_verify_cleartext(src, signer=None):
    ret, _, err = run_proc(
        GPG, ['--homedir', GPGDIR, '--batch', '--yes', '--trust-model', 'always', '--verify', src])
    if ret != 0:
        raise_err('gpg cleartext verification failed', err)
    # Check GPG output
    match = re.match(RE_GPG_GOOD_SIGNATURE, err)
    if not match:
        raise_err('wrong gpg verification output', err)
    if signer and (not match.group(1) == signer):
        raise_err('gpg verification failed, wrong signer')


def gpg_sign_file(src, dst, signer, z=None, armor=False):
    params = ['--homedir', GPGDIR, '--pinentry-mode=loopback', '--batch', '--yes',
              '--passphrase', PASSWORD, '--trust-model', 'always', '-u', signer, '-o', dst, '-s', src]
    if z: gpg_params_insert_z(params, 3, z)
    if armor: params.insert(2, '--armor')
    ret, _, err = run_proc(GPG, params)
    if ret != 0:
        raise_err('gpg signing failed', err)


def gpg_sign_detached(src, signer, armor=False):
    params = ['--homedir', GPGDIR, '--pinentry-mode=loopback', '--batch', '--yes',
              '--passphrase', PASSWORD, '--trust-model', 'always', '-u', signer, '--detach-sign', src]
    if armor: params.insert(2, '--armor')
    ret, _, err = run_proc(GPG, params)
    if ret != 0:
        raise_err('gpg detached signing failed', err)


def gpg_sign_cleartext(src, dst, signer):
    params = ['--homedir', GPGDIR, '--pinentry-mode=loopback', '--batch', '--yes', '--passphrase',
              PASSWORD, '--trust-model', 'always', '-u', signer, '-o', dst, '--clearsign', src]
    ret, _, err = run_proc(GPG, params)
    if ret != 0:
        raise_err('gpg cleartext signing failed', err)


def gpg_agent_clear_cache():
    run_proc(GPGCONF, ['--homedir', GPGDIR, '--kill', 'gpg-agent'])

'''
    Things to try here later on:
    - different symmetric algorithms
    - different file sizes (block len/packet len tests)
    - different public key algorithms
    - different compression levels/algorithms
'''


def gpg_to_rnp_encryption(filesize, cipher=None, z=None):
    '''
    Encrypts with GPG and decrypts with RNP
    '''
    src, dst, dec = reg_workfiles('cleartext', '.txt', '.gpg', '.rnp')
    # Generate random file of required size
    random_text(src, filesize)
    for armor in [False, True]:
        # Encrypt cleartext file with GPG
        gpg_encrypt_file(src, dst, cipher, z, armor)
        # Decrypt encrypted file with RNP
        rnp_decrypt_file(dst, dec)
        compare_files(src, dec, 'rnp decrypted data differs')
        remove_files(dst, dec)
    clear_workfiles()


def file_encryption_rnp_to_gpg(filesize, z=None):
    '''
    Encrypts with RNP and decrypts with GPG and RNP
    '''
    # TODO: Would be better to do "with reg_workfiles() as src,dst,enc ... and
    # do cleanup at the end"
    src, dst, enc = reg_workfiles('cleartext', '.txt', '.gpg', '.rnp')
    # Generate random file of required size
    random_text(src, filesize)
    for armor in [False, True]:
        # Encrypt cleartext file with RNP
        rnp_encrypt_file_ex(src, enc, [KEY_ENCRYPT], None, None, None, z, armor)
        # Decrypt encrypted file with GPG
        gpg_decrypt_file(enc, dst, PASSWORD)
        compare_files(src, dst, 'gpg decrypted data differs')
        remove_files(dst)
        # Decrypt encrypted file with RNP
        rnp_decrypt_file(enc, dst)
        compare_files(src, dst, 'rnp decrypted data differs')
        remove_files(enc, dst)
    clear_workfiles()

'''
    Things to try later:
    - different public key algorithms
    - decryption with generated by GPG and imported keys
'''


def rnp_sym_encryption_gpg_to_rnp(filesize, cipher = None, z = None):
    src, dst, dec = reg_workfiles('cleartext', '.txt', '.gpg', '.rnp')
    # Generate random file of required size
    random_text(src, filesize)
    for armor in [False, True]:
        # Encrypt cleartext file with GPG
        gpg_symencrypt_file(src, dst, cipher, z, armor)
        # Decrypt encrypted file with RNP
        rnp_decrypt_file(dst, dec)
        compare_files(src, dec, 'rnp decrypted data differs')
        remove_files(dst, dec)
    clear_workfiles()


def rnp_sym_encryption_rnp_to_gpg(filesize, cipher = None, z = None):
    src, dst, enc = reg_workfiles('cleartext', '.txt', '.gpg', '.rnp')
    # Generate random file of required size
    random_text(src, filesize)
    for armor in [False, True]:
        # Encrypt cleartext file with RNP
        rnp_encrypt_file_ex(src, enc, None, [PASSWORD], None, cipher, z, armor)
        # Decrypt encrypted file with GPG
        gpg_decrypt_file(enc, dst, PASSWORD)
        compare_files(src, dst, 'gpg decrypted data differs')
        remove_files(dst)
        # Decrypt encrypted file with RNP
        rnp_decrypt_file(enc, dst)
        compare_files(src, dst, 'rnp decrypted data differs')
        remove_files(enc, dst)
    clear_workfiles()

def rnp_sym_encryption_rnp_aead(filesize, cipher = None, z = None, aead = None, usegpg = False):
    src, dst, enc = reg_workfiles('cleartext', '.txt', '.rnp', '.enc')
    # Generate random file of required size
    random_text(src, filesize)
    # Encrypt cleartext file with RNP
    rnp_encrypt_file_ex(src, enc, None, [PASSWORD], aead, cipher, z)
    # Decrypt encrypted file with RNP
    rnp_decrypt_file(enc, dst)
    compare_files(src, dst, 'rnp decrypted data differs')
    remove_files(dst)

    if usegpg:
        # Decrypt encrypted file with GPG
        gpg_decrypt_file(enc, dst, PASSWORD)
        compare_files(src, dst, 'gpg decrypted data differs')
        remove_files(dst, enc)
        # Encrypt cleartext file with GPG
        gpg_symencrypt_file(src, enc, cipher, z, False, aead)
        # Decrypt encrypted file with RNP
        rnp_decrypt_file(enc, dst)
        compare_files(src, dst, 'rnp decrypted data differs')

    clear_workfiles()

def rnp_signing_rnp_to_gpg(filesize):
    src, sig, ver = reg_workfiles('cleartext', '.txt', '.sig', '.ver')
    # Generate random file of required size
    random_text(src, filesize)
    for armor in [False, True]:
        # Sign file with RNP
        rnp_sign_file(src, sig, [KEY_SIGN_RNP], [PASSWORD], armor)
        # Verify signed file with RNP
        rnp_verify_file(sig, ver, KEY_SIGN_RNP)
        compare_files(src, ver, 'rnp verified data differs')
        remove_files(ver)
        # Verify signed message with GPG
        gpg_verify_file(sig, ver, KEY_SIGN_RNP)
        compare_files(src, ver, 'gpg verified data differs')
        remove_files(sig, ver)
    clear_workfiles()


def rnp_detached_signing_rnp_to_gpg(filesize):
    src, sig, asc = reg_workfiles('cleartext', '.txt', '.txt.sig', '.txt.asc')
    # Generate random file of required size
    random_text(src, filesize)
    for armor in [True, False]:
        # Sign file with RNP
        rnp_sign_detached(src, [KEY_SIGN_RNP], [PASSWORD], armor)
        sigpath = asc if armor else sig
        # Verify signature with RNP
        rnp_verify_detached(sigpath, KEY_SIGN_RNP)
        # Verify signed message with GPG
        gpg_verify_detached(src, sigpath, KEY_SIGN_RNP)
        remove_files(sigpath)
    clear_workfiles()


def rnp_cleartext_signing_rnp_to_gpg(filesize):
    src, asc = reg_workfiles('cleartext', '.txt', '.txt.asc')
    # Generate random file of required size
    random_text(src, filesize)
    # Sign file with RNP
    rnp_sign_cleartext(src, asc, [KEY_SIGN_RNP], [PASSWORD])
    # Verify signature with RNP
    rnp_verify_cleartext(asc, KEY_SIGN_RNP)
    # Verify signed message with GPG
    gpg_verify_cleartext(asc, KEY_SIGN_RNP)
    clear_workfiles()


def rnp_signing_gpg_to_rnp(filesize, z=None):
    src, sig, ver = reg_workfiles('cleartext', '.txt', '.sig', '.ver')
    # Generate random file of required size
    random_text(src, filesize)
    for armor in [True, False]:
        # Sign file with GPG
        gpg_sign_file(src, sig, KEY_SIGN_GPG, z, armor)
        # Verify file with RNP
        rnp_verify_file(sig, ver, KEY_SIGN_GPG)
        compare_files(src, ver, 'rnp verified data differs')
        remove_files(sig, ver)
    clear_workfiles()


def rnp_detached_signing_gpg_to_rnp(filesize):
    src, sig, asc = reg_workfiles('cleartext', '.txt', '.txt.sig', '.txt.asc')
    # Generate random file of required size
    random_text(src, filesize)
    for armor in [True, False]:
        # Sign file with GPG
        gpg_sign_detached(src, KEY_SIGN_GPG, armor)
        sigpath = asc if armor else sig
        # Verify file with RNP
        rnp_verify_detached(sigpath, KEY_SIGN_GPG)
    clear_workfiles()


def rnp_cleartext_signing_gpg_to_rnp(filesize):
    src, asc = reg_workfiles('cleartext', '.txt', '.txt.asc')
    # Generate random file of required size
    random_text(src, filesize)
    # Sign file with GPG
    gpg_sign_cleartext(src, asc, KEY_SIGN_GPG)
    # Verify signature with RNP
    rnp_verify_cleartext(asc, KEY_SIGN_GPG)
    # Verify signed message with GPG
    gpg_verify_cleartext(asc, KEY_SIGN_GPG)
    clear_workfiles()

def gpg_supports_aead():
    ret, out, err = run_proc(GPG, ["--version"])
    if re.match(r'(?s)^.*AEAD:\s+EAX,\s+OCB.*', out):
        return True
    else:
        return False

def setup(loglvl):
    # Setting up directories.
    global RMWORKDIR, WORKDIR, RNPDIR, RNP, RNPK, GPG, GPGDIR, GPGCONF
    logging.basicConfig(stream=sys.stderr, format="%(message)s")
    logging.getLogger().setLevel(loglvl)
    WORKDIR = os.getcwd()
    if not '/tmp/' in WORKDIR:
        WORKDIR = tempfile.mkdtemp(prefix='rnpctmp')
        RMWORKDIR = True

    logging.info('Running in ' + WORKDIR)

    RNPDIR = path.join(WORKDIR, '.rnp')
    RNP = os.getenv('RNP_TESTS_RNP_PATH') or 'rnp'
    RNPK = os.getenv('RNP_TESTS_RNPKEYS_PATH') or 'rnpkeys'
    os.mkdir(RNPDIR, 0700)

    GPGDIR = path.join(WORKDIR, '.gpg')
    GPG = os.getenv('RNP_TESTS_GPG_PATH') or find_utility('gpg')
    GPGCONF = os.getenv('RNP_TESTS_GPGCONF_PATH') or find_utility('gpgconf')
    os.mkdir(GPGDIR, 0700)

def data_path(subpath):
    ''' Constructs path to the tests data file/dir'''
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', subpath)

def key_path(file_base_name, secret):
    ''' Constructs path to the .gpg file'''
    path=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/cli_EncryptSign', file_base_name)
    return ''.join([path, '-sec' if secret else '', '.gpg'])

class TestIdMixin(object):

    @property
    def test_id(self):
        return "".join(self.id().split('.')[1:3])

class KeyLocationChooserMixin(object):
    def __init__(self):
        # If set it will try to import a key from provided location
        # otherwise it will try to generate a key
        self.__op_key_location = None
        self.__op_key_gen_cmd = None

    @property
    def operation_key_location(self):
        return self.__op_key_location

    @operation_key_location.setter
    def operation_key_location(self, key):
        if (type(key) is not tuple): raise RuntimeError("Key must be tuple(pub,sec)")
        self.__op_key_location = key
        self.__op_key_gen_cmd = None

    @property
    def operation_key_gencmd(self):
        return self.__op_key_gen_cmd

    @operation_key_gencmd.setter
    def operation_key_gencmd(self, cmd):
        self.__op_key_gen_cmd = cmd
        self.__op_key_location = None

'''
    Things to try here later on:
    - different public key algorithms
    - different key protection levels/algorithms
    - armored import/export
'''
class Keystore(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        clear_keyrings()

    def tearDown(self):
        clear_workfiles()

    @staticmethod
    def _rnpkey_generate_rsa(bits= None):
        # Setup command line params
        if bits:
            params = ['--numbits', str(bits)]
        else:
            params = []
            bits = 2048

        userid = str(bits) + '@rnptest'
        # Open pipe for password
        pipe = pswd_pipe(PASSWORD)
        params = params + ['--homedir', RNPDIR, '--pass-fd',
                        str(pipe), '--userid', userid, '--generate-key']
        # Run key generation
        ret, out, err = run_proc(RNPK, params)
        os.close(pipe)
        if ret != 0:
            raise_err('key generation failed', err)
        # Check packets using the gpg
        match = check_packets(path.join(RNPDIR, 'pubring.gpg'), RE_RSA_KEY)
        if not match:
            raise_err('generated key check failed')
        keybits = int(match.group(1))
        if keybits > bits or keybits <= bits - 8:
            raise_err('wrong key bits')
        keyid = match.group(2)
        if not match.group(3) == userid:
            raise_err('wrong user id')
        # List keys using the rnpkeys
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
        if ret != 0:
            raise_err('key list failed', err)
        match = re.match(RE_RSA_KEY_LIST, out)
        # Compare key ids
        if not match:
            raise_err('wrong key list output', out)
        if not match.group(3)[-16:] == match.group(2) or not match.group(2) == keyid.lower():
            raise_err('wrong key ids')
        if not match.group(1) == str(bits):
            raise_err('wrong key bits in list')
        # Import key to the gnupg
        ret, out, err = run_proc(GPG, ['--batch', '--passphrase', PASSWORD, '--homedir', GPGDIR,
                                    '--import', path.join(RNPDIR, 'pubring.gpg'), path.join(RNPDIR, 'secring.gpg')])
        if ret != 0:
            raise_err('gpg key import failed', err)
        # Cleanup and return
        clear_keyrings()

    def test_generate_default_rsa_key(self):
        Keystore._rnpkey_generate_rsa()

    def test_generate_multiple_rsa_key__check_if_available(self):
        '''
        Generate multiple RSA keys and check if they are all available
        '''
        clear_keyrings()
        # Generate 5 keys with different user ids
        for i in range(0, 5):
            # generate the next key
            pipe = pswd_pipe(PASSWORD)
            userid = str(i) + '@rnp-multiple'
            ret, out, err = run_proc(RNPK, ['--numbits', '2048', '--homedir', RNPDIR,
                                            '--pass-fd', str(pipe), '--userid', userid, '--generate-key'])
            os.close(pipe)
            if ret != 0:
                raise_err('key generation failed', err)
            # list keys using the rnpkeys, checking whether it reports correct key
            # number
            ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
            if ret != 0:
                raise_err('key list failed', err)
            match = re.match(RE_MULTIPLE_KEY_LIST, out)
            if not match:
                raise_err('wrong key list output', out)
            if not match.group(1) == str((i + 1) * 2):
                raise_err('wrong key count', out)

        # Checking the 5 keys output
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
        if ret != 0:
            raise_err('key list failed', err)
        match = re.match(RE_MULTIPLE_KEY_5, out)
        if not match:
            raise_err('wrong key list output', out)

        # Cleanup and return
        clear_keyrings()

    def test_generate_key_with_gpg_import_to_rnp(self):
        '''
        Generate key with GnuPG and import it to rnp
        '''
        # Generate key in GnuPG
        ret, out, err = run_proc(GPG, ['--batch', '--homedir', GPGDIR,
                                    '--passphrase', '', '--quick-generate-key', 'rsakey@gpg', 'rsa'])
        if ret != 0:
            raise_err('gpg key generation failed, error ' + str(ret) , err)
        # Getting fingerprint of the generated key
        ret, out, err = run_proc(
            GPG, ['--batch', '--homedir', GPGDIR, '--list-keys'])
        match = re.match(RE_GPG_SINGLE_RSA_KEY, out)
        if not match:
            raise_err('wrong gpg key list output', out)
        keyfp = match.group(1)
        # Exporting generated public key
        ret, out, err = run_proc(
            GPG, ['--batch', '--homedir', GPGDIR, '--armor', '--export', keyfp])
        if ret != 0:
            raise_err('gpg : public key export failed', err)
        pubpath = path.join(RNPDIR, keyfp + '-pub.asc')
        with open(pubpath, 'w+') as f:
            f.write(out)
        # Exporting generated secret key
        ret, out, err = run_proc(
            GPG, ['--batch', '--homedir', GPGDIR, '--armor', '--export-secret-key', keyfp])
        if ret != 0:
            raise_err('gpg : secret key export failed', err)
        secpath = path.join(RNPDIR, keyfp + '-sec.asc')
        with open(secpath, 'w+') as f:
            f.write(out)
        # Importing public key to rnp
        ret, out, err = run_proc(
            RNPK, ['--homedir', RNPDIR, '--import-key', pubpath])
        if ret != 0:
            raise_err('rnp : public key import failed', err)
        # Importing secret key to rnp
        ret, out, err = run_proc(
            RNPK, ['--homedir', RNPDIR, '--import-key', secpath])
        if ret != 0:
            raise_err('rnp : secret key import failed', err)
        # We do not check keyrings after the import - imported by RNP keys are not
        # saved yet

    def test_generate_with_rnp_import_to_gpg(self):
        '''
        Generate key with RNP and export it and then import to GnuPG
        '''
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


class Misc(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        rnp_genkey_rsa(KEY_ENCRYPT)
        rnp_genkey_rsa(KEY_SIGN_GPG)
        gpg_import_pubring()
        gpg_import_secring()

    def tearDown(self):
        clear_workfiles()

    def test_encryption_no_mdc(self):
        src, dst, dec = reg_workfiles('cleartext', '.txt', '.gpg', '.rnp')
        # Generate random file of required size
        random_text(src, 64000)
        # Encrypt cleartext file with GPG
        params = ['--homedir', GPGDIR, '-c', '-z', '0', '--disable-mdc', '--s2k-count', '65536', '--batch', '--passphrase', PASSWORD, '--output', dst, src]
        ret, _, err = run_proc(GPG, params)
        if ret != 0:
            raise_err('gpg symmetric encryption failed', err)
        # Decrypt encrypted file with RNP
        rnp_decrypt_file(dst, dec)
        compare_files(src, dec, 'rnp decrypted data differs')

    def test_encryption_s2k(self):
        src, dst, dec = reg_workfiles('cleartext', '.txt', '.gpg', '.rnp')
        random_text(src, 64000)

        ciphers = ['AES', 'AES192', 'AES256', 'TWOFISH', 'CAMELLIA128',
                'CAMELLIA192', 'CAMELLIA256', 'IDEA', '3DES', 'CAST5', 'BLOWFISH']
        hashes = ['SHA1', 'RIPEMD160', 'SHA256', 'SHA384', 'SHA512', 'SHA224']
        s2kmodes = [0, 1, 3]

        def rnp_encryption_s2k_gpg(cipher, hash_alg, s2k=None, iterations=None):
            params = ['--homedir', GPGDIR, '-c', '--s2k-cipher-algo', cipher, '--s2k-digest-algo',
                    hash_alg, '--batch', '--passphrase', PASSWORD, '--output', dst, src]

            if s2k is not None:
                params.insert(7, '--s2k-mode')
                params.insert(8, str(s2k))

                if iterations is not None:
                    params.insert(9, '--s2k-count')
                    params.insert(10, str(iterations))

            ret, _, err = run_proc(GPG, params)
            if ret != 0:
                raise_err('gpg symmetric encryption failed', err)
            rnp_decrypt_file(dst, dec)
            compare_files(src, dec, 'rnp decrypted data differs')
            remove_files(dst, dec)

        for i in range(0, 80):
            rnp_encryption_s2k_gpg(ciphers[i % len(ciphers)], hashes[
                                i % len(hashes)], s2kmodes[i % len(s2kmodes)])

    def test_armor(self):
        src_beg, dst_beg, dst_mid, dst_fin = reg_workfiles('beg','.src','.dst', '.mid.dst', '.fin.dst')
        armor_types = [('msg', 'MESSAGE'), ('pubkey', 'PUBLIC KEY BLOCK'), ('seckey', 'PRIVATE KEY BLOCK'), ('sign', 'SIGNATURE')]

        for data_type, header in armor_types:
            random_text(src_beg, 1000)
            prefix = '-----BEGIN PGP ' + header + '-----'
            suffix = '-----END PGP ' + header + '-----'

            run_proc(RNP, ['--enarmor', data_type, src_beg, '--output', dst_beg])
            txt = file_text(dst_beg).strip('\r\n')

            if not (txt.startswith(prefix) and txt.endswith(suffix)):
                raise_err('wrong armor header or trailer', txt)

            run_proc(RNP, ['--dearmor', dst_beg, '--output', dst_mid])
            run_proc(RNP, ['--enarmor', data_type, dst_mid, '--output', dst_fin])

            compare_files(dst_beg, dst_fin, "RNP armor/dearmor test failed")
            compare_files(src_beg, dst_mid, "RNP armor/dearmor test failed")
            remove_files(dst_beg, dst_mid, dst_fin)

    def test_rnpkeys_lists(self):
        path = data_path('test_cli_rnpkeys') + '/'

        _, out, _ = run_proc(RNPK, ['--homedir', data_path('keyrings/1'), '--list-keys'])
        compare_file(path + 'keyring_1_list_keys', out, 'keyring 1 key listing failed')
        _, out, _ = run_proc(RNPK, ['--hom', data_path('keyrings/1'), '-l', '--with-sigs'])
        compare_file(path + 'keyring_1_list_sigs', out, 'keyring 1 sig listing failed')
        _, out, _ = run_proc(RNPK, ['--home', data_path('keyrings/1'), '--list-keys', '--secret'])
        compare_file(path + 'keyring_1_list_keys_sec', out, 'keyring 1 sec key listing failed')
        _, out, _ = run_proc(RNPK, ['--home', data_path('keyrings/1'), '--list-keys', '--secret', '--with-sigs'])
        compare_file(path + 'keyring_1_list_sigs_sec', out, 'keyring 1 sec sig listing failed')

        _, out, _ = run_proc(RNPK, ['--homedir', data_path('keyrings/2'), '--list-keys'])
        compare_file(path + 'keyring_2_list_keys', out, 'keyring 2 key listing failed')
        _, out, _ = run_proc(RNPK, ['--homedir', data_path('keyrings/2'), '-l', '--with-sigs'])
        compare_file(path + 'keyring_2_list_sigs', out, 'keyring 2 sig listing failed')

        _, out, _ = run_proc(RNPK, ['--homedir', data_path('keyrings/3'), '--list-keys'])
        compare_file(path + 'keyring_3_list_keys', out, 'keyring 3 key listing failed')
        _, out, _ = run_proc(RNPK, ['--homedir', data_path('keyrings/3'), '-l', '--with-sigs'])
        compare_file(path + 'keyring_3_list_sigs', out, 'keyring 3 sig listing failed')

        _, out, _ = run_proc(RNPK, ['--homedir', data_path('keyrings/5'), '--list-keys'])
        compare_file(path + 'keyring_5_list_keys', out, 'keyring 5 key listing failed')
        _, out, _ = run_proc(RNPK, ['--homedir', data_path('keyrings/5'), '-l', '--with-sigs'])
        compare_file(path + 'keyring_5_list_sigs', out, 'keyring 5 sig listing failed')

        _, out, _ = run_proc(RNPK, ['--homedir', data_path('test_stream_key_load/g10'), '--list-keys'])
        compare_file(path + 'test_stream_key_load_keys', out, 'g10 keyring key listing failed')
        _, out, _ = run_proc(RNPK, ['--homedir', data_path('test_stream_key_load/g10'), '-l', '--with-sigs'])
        compare_file(path + 'test_stream_key_load_sigs', out, 'g10 keyring sig listing failed')
        # Below are disabled until we have some kind of sorting which doesn't depend on readdir order
        #_, out, _ = run_proc(RNPK, ['--homedir', data_path('test_stream_key_load/g10'), '-l', '--secret'])
        #compare_file(path + 'test_stream_key_load_keys_sec', out, 'g10 sec keyring key listing failed')
        #_, out, _ = run_proc(RNPK, ['--homedir', data_path('test_stream_key_load/g10'), '-l', '--secret', '--with-sigs'])
        #compare_file(path + 'test_stream_key_load_sigs_sec', out, 'g10 sec keyring sig listing failed')

        _, out, _ = run_proc(RNPK, ['--homedir', data_path('keyrings/1'), '-l', '2fcadf05ffa501bb'])
        compare_file(path + 'getkey_2fcadf05ffa501bb', out, 'list key 2fcadf05ffa501bb failed')
        _, out, _ = run_proc(RNPK, ['--homedir', data_path('keyrings/1'), '-l', '--with-sigs', '2fcadf05ffa501bb'])
        compare_file(path + 'getkey_2fcadf05ffa501bb_sig', out, 'list sig 2fcadf05ffa501bb failed')
        _, out, _ = run_proc(RNPK, ['--homedir', data_path('keyrings/1'), '-l', '--secret', '2fcadf05ffa501bb'])
        compare_file(path + 'getkey_2fcadf05ffa501bb_sec', out, 'list sec 2fcadf05ffa501bb failed')

        _, out, err = run_proc(RNPK, ['--homedir', data_path('keyrings/1'), '-l', '00000000'])
        compare_file(path + 'getkey_00000000', out, 'list key 00000000 failed')
        _, out, err = run_proc(RNPK, ['--homedir', data_path('keyrings/1'), '-l', 'zzzzzzzz'])
        compare_file(path + 'getkey_zzzzzzzz', out, 'list key zzzzzzzz failed')

    def test_rnpkeys_g10_list_order(self):
        _, out, _ = run_proc(RNPK, ['--homedir', data_path('test_stream_key_load/g10'), '--list-keys'])
        compare_file(data_path('test_cli_rnpkeys/g10_list_keys'), out, 'g10 key listing failed')
        _, out, _ = run_proc(RNPK, ['--homedir', data_path('test_stream_key_load/g10'), '--secret', '--list-keys'])
        compare_file(data_path('test_cli_rnpkeys/g10_list_keys_sec'), out, 'g10 secret key listing failed')
        return

    def test_rnpkeys_g10_def_key(self):
        RE_SIG = r'(?s)^.*' \
        r'Good signature made .*' \
        r'using (.*) key (.*)' \
        r'pub .*' \
        r'b54fdebbb673423a5d0aa54423674f21b2441527.*' \
        r'uid\s+(ecc-p256)\s*' \
        r'Signature\(s\) verified successfully.*$'

        src, dst = reg_workfiles('cleartext', '.txt', '.rnp')
        random_text(src, 1000)
        # Sign file with rnp using the default g10 key
        params = ['--homedir', data_path('test_cli_g10_defkey/g10'), '--password', PASSWORD, '--output', dst, '-s', src]
        ret, _, err = run_proc(RNP, params)
        if ret != 0:
            raise_err('rnp signing failed', err)
        # Verify signed file
        params = ['--homedir', data_path('test_cli_g10_defkey/g10'), '-v', dst]
        ret, out, err = run_proc(RNP, params)
        if ret != 0:
            raise_err('verification failed', err)
        match = re.match(RE_SIG, err)
        if not match:
            raise_err('wrong rnp g10 verification output', err)
        return
    
    def test_large_packet(self):
        # Verifying large packet file with GnuPG
        ret, _, err = run_proc(GPG, ['--homedir', GPGDIR, '--keyring', data_path('keyrings/1/pubring.gpg'), '--verify', data_path('test_large_packet/4g.bzip2.gpg')])
        if ret != 0:
            raise_err('large packet verification failed', err)
        return

    def test_partial_length_signature(self):
        # Verifying partial length signature with GnuPG
        ret, _, _ = run_proc(GPG, ['--homedir', GPGDIR, '--keyring', data_path('keyrings/1/pubring.gpg'), '--verify', data_path('test_partial_length/message.txt.partial-signed')])
        if ret == 0:
            raise_err('partial length signature packet should result in failure but did not')
        return

<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> Added tests for keyring having public key in partial length packets #939 (part two)
    def test_partial_length_public_key(self):
        # Reading keyring that has a public key packet with partial length using GnuPG
        ret, _, _ = run_proc(GPG, ['--homedir', GPGDIR, '--keyring', data_path('test_partial_length/pubring.gpg.partial'), '--list-keys'])
        if ret == 0:
            raise_err('partial length public key packet should result in failure but did not')
        return

<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> Added a tests for message in partial packets having 0-size last chunk #939 (part four)
    def test_partial_length_zero_last_chunk(self):
        # Verifying message in partial packets having 0-size last chunk with GnuPG
        ret, _, err = run_proc(GPG, ['--homedir', GPGDIR, '--keyring', data_path('keyrings/1/pubring.gpg'), '--verify', data_path('test_partial_length/message.txt.partial-zero-last')])
        if ret != 0:
            raise_err('message in partial packets having 0-size last chunk verification failed', err)
        return

<<<<<<< HEAD
    def test_partial_length_largest(self):
        # Verifying message having largest possible partial packet with GnuPG
        ret, _, err = run_proc(GPG, ['--homedir', GPGDIR, '--keyring', data_path('keyrings/1/pubring.gpg'), '--verify', data_path('test_partial_length/message.txt.partial-1g')])
        if ret != 0:
            raise_err('message having largest possible partial packet verification failed', err)
        return

=======
>>>>>>> Added tests for message having signature in partial length packets #939 (part one)
=======
>>>>>>> Added tests for keyring having public key in partial length packets #939 (part two)
=======
>>>>>>> Added a tests for message in partial packets having 0-size last chunk #939 (part four)
    def test_rnp_list_packets(self):
        # List packets in humand-readable format
        params = ['--list-packets', data_path('test_list_packets/ecc-p256-pub.asc')]
        ret, out, err = run_proc(RNP, params)
        if ret != 0:
            raise_err('packet listing failed', err)
        compare_file_ex(data_path('test_list_packets/list_standard.txt'), out, 'standard listing mismatch')
        # List packets with mpi values
        params = ['--mpi', '--list-packets', data_path('test_list_packets/ecc-p256-pub.asc')]
        ret, out, err = run_proc(RNP, params)
        if ret != 0:
            raise_err('packet listing with mpi failed', err)
        compare_file_ex(data_path('test_list_packets/list_mpi.txt'), out, 'mpi listing mismatch')
        # List packets with grip/fingerprint values
        params = ['--list-packets', data_path('test_list_packets/ecc-p256-pub.asc'), '--grips']
        ret, out, err = run_proc(RNP, params)
        if ret != 0:
            raise_err('packet listing with grips failed', err)
        compare_file_ex(data_path('test_list_packets/list_grips.txt'), out, 'grips listing mismatch')
        # List packets with raw packet contents
        params = ['--list-packets', data_path('test_list_packets/ecc-p256-pub.asc'), '--raw']
        ret, out, err = run_proc(RNP, params)
        if ret != 0:
            raise_err('packet listing with raw packets failed', err)
        compare_file_ex(data_path('test_list_packets/list_raw.txt'), out, 'raw listing mismatch')
        # List packets with all options enabled
        params = ['--list-packets', data_path('test_list_packets/ecc-p256-pub.asc'), '--grips', '--raw', '--mpi']
        ret, out, err = run_proc(RNP, params)
        if ret != 0:
            raise_err('packet listing with all options failed', err)
        compare_file_ex(data_path('test_list_packets/list_all.txt'), out, 'all listing mismatch')

        # List packets with JSON output
        params = ['--json', '--list-packets', data_path('test_list_packets/ecc-p256-pub.asc')]
        ret, out, err = run_proc(RNP, params)
        if ret != 0:
            raise_err('json packet listing failed', err)
        compare_file_ex(data_path('test_list_packets/list_json.txt'), out, 'json listing mismatch')
        # List packets with mpi values, JSON output
        params = ['--json', '--mpi', '--list-packets', data_path('test_list_packets/ecc-p256-pub.asc')]
        ret, out, err = run_proc(RNP, params)
        if ret != 0:
            raise_err('json mpi packet listing failed', err)
        compare_file_ex(data_path('test_list_packets/list_json_mpi.txt'), out, 'json mpi listing mismatch')
        # List packets with grip/fingerprint values, JSON output
        params = ['--json', '--grips', '--list-packets', data_path('test_list_packets/ecc-p256-pub.asc')]
        ret, out, err = run_proc(RNP, params)
        if ret != 0:
            raise_err('json grips packet listing failed', err)
        compare_file_ex(data_path('test_list_packets/list_json_grips.txt'), out, 'json grips listing mismatch')
        # List packets with raw packet values, JSON output
        params = ['--json', '--raw', '--list-packets', data_path('test_list_packets/ecc-p256-pub.asc')]
        ret, out, err = run_proc(RNP, params)
        if ret != 0:
            raise_err('json raw packet listing failed', err)
        compare_file_ex(data_path('test_list_packets/list_json_raw.txt'), out, 'json raw listing mismatch')
        # List packets with all values, JSON output
        params = ['--json', '--raw', '--list-packets', data_path('test_list_packets/ecc-p256-pub.asc'), '--mpi', '--grips']
        ret, out, err = run_proc(RNP, params)
        if ret != 0:
            raise_err('json all listing failed', err)
        compare_file_ex(data_path('test_list_packets/list_json_all.txt'), out, 'json all listing mismatch')
        return

class Encryption(unittest.TestCase):
    '''
        Things to try later:
        - different public key algorithms
        - different hash algorithms where applicable

        TODO:
        Tests in this test case should be splitted into many algorithm-specific tests (potentially auto generated)
        Reason being - if you have a problem with BLOWFISH size 1000000, you don't want to wait until everything else gets
        tested before your failing BLOWFISH
    '''
    # Ciphers list tro try during encryption. None will use default
    CIPHERS = [None, 'AES', 'AES192', 'AES256', 'TWOFISH', 'CAMELLIA128', 'CAMELLIA192', 'CAMELLIA256', 'IDEA', '3DES', 'CAST5', 'BLOWFISH']
    SIZES = [20, 40, 120, 600, 1000, 5000, 20000, 150000, 1000000]
    # Compression parameters to try during encryption(s)
    Z = [[None, 0], ['zip'], ['zlib'], ['bzip2'], [None, 1], [None, 9]]
    # Number of test runs - each run picks next encryption algo and size, wrapping on array
    RUNS = 60

    @classmethod
    def setUpClass(cls):
        # Generate keypair in RNP
        rnp_genkey_rsa(KEY_ENCRYPT)
        # Add some other keys to the keyring
        rnp_genkey_rsa('dummy1@rnp', 1024)
        rnp_genkey_rsa('dummy2@rnp', 1024)
        gpg_import_pubring()
        gpg_import_secring()
        Encryption.CIPHERS_R = list_upto(Encryption.CIPHERS, Encryption.RUNS)
        Encryption.SIZES_R = list_upto(Encryption.SIZES, Encryption.RUNS)
        Encryption.Z_R = list_upto(Encryption.Z, Encryption.RUNS)

    @classmethod
    def tearDownClass(cls):
        clear_keyrings()

    def tearDown(self):
        clear_workfiles()

    # Encrypt cleartext file with GPG and decrypt it with RNP, using different ciphers and file sizes
    def test_file_encryption__gpg_to_rnp(self):
        for size, cipher in zip(Encryption.SIZES_R, Encryption.CIPHERS_R):
            gpg_to_rnp_encryption(size, cipher)

    # Encrypt with RNP and decrypt with GPG
    def test_file_encryption__rnp_to_gpg(self):
        for size in Encryption.SIZES:
            file_encryption_rnp_to_gpg(size)

    def test_sym_encryption__gpg_to_rnp(self):
        # Encrypt cleartext with GPG and decrypt with RNP
        for size, cipher, z in zip(Encryption.SIZES_R, Encryption.CIPHERS_R, Encryption.Z_R):
            rnp_sym_encryption_gpg_to_rnp(size, cipher, z)

    def test_sym_encryption__rnp_to_gpg(self):
        # Encrypt cleartext with RNP and decrypt with GPG
        for size, cipher, z in zip(Encryption.SIZES_R, Encryption.CIPHERS_R, Encryption.Z_R):
            rnp_sym_encryption_rnp_to_gpg(size, cipher, z)

    def test_sym_encryption__rnp_aead(self):
        AEAD_C = list_upto(['AES', 'AES192', 'AES256', 'TWOFISH', 'CAMELLIA128', 'CAMELLIA192', 'CAMELLIA256'], Encryption.RUNS)
        AEAD_M = list_upto([None, 'eax', 'ocb'], Encryption.RUNS)
        AEAD_B = list_upto([None, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 18, 24, 30, 40, 50, 56], Encryption.RUNS)

        usegpg = gpg_supports_aead()

        # Encrypt and decrypt cleartext using the AEAD
        for size, cipher, aead, bits, z in zip(Encryption.SIZES_R, AEAD_C, AEAD_M, AEAD_B, Encryption.Z_R):
            rnp_sym_encryption_rnp_aead(size, cipher, z, [aead, bits], usegpg)

    def test_encryption_multiple_recipients(self):
        USERIDS = ['key1@rnp', 'key2@rnp', 'key3@rnp']
        KEYPASS = ['key1pass', 'key2pass', 'key3pass']
        PASSWORDS = ['password1', 'password2', 'password3']
        # Generate multiple keys and import to GnuPG
        for uid, pswd in zip(USERIDS, KEYPASS):
            rnp_genkey_rsa(uid, 1024, pswd)

        gpg_import_pubring()
        gpg_import_secring()

        KEYPSWD = tuple((t1, t2) for t1 in range(len(USERIDS) + 1) for t2 in range(len(PASSWORDS) + 1))
        KEYPSWD = list_upto(KEYPSWD, Encryption.RUNS)
        if gpg_supports_aead():
            AEADS = list_upto([None, [None], ['eax'], ['ocb']], Encryption.RUNS)
        else:
            AEADS = list_upto([None], Encryption.RUNS)

        src, dst, dec = reg_workfiles('cleartext', '.txt', '.rnp', '.dec')
        # Generate random file of required size
        random_text(src, 128000)

        for kpswd, aead in zip(KEYPSWD, AEADS):
            keynum, pswdnum = kpswd
            if (keynum == 0) and (pswdnum == 0):
                continue

            uids = USERIDS[:keynum] if keynum else None
            pswds = PASSWORDS[:pswdnum] if pswdnum else None

            rnp_encrypt_file_ex(src, dst, uids, pswds, aead)

            # Decrypt file with each of the keys, we have different password for each key
            for pswd in KEYPASS[:keynum]:
                gpg_decrypt_file(dst, dec, pswd)
                gpg_agent_clear_cache()
                remove_files(dec)
                rnp_decrypt_file(dst, dec, '\n'.join([pswd] * 5))

            # GPG decrypts only with first password, see T3795
            if (not aead) and pswdnum:
                gpg_decrypt_file(dst, dec, PASSWORDS[0])
                gpg_agent_clear_cache
                remove_files(dec)

            # Decrypt file with each of the passwords
            for pswd in PASSWORDS[:pswdnum]:
                if aead:
                    gpg_decrypt_file(dst, dec, pswd)
                    gpg_agent_clear_cache()
                    remove_files(dec)
                rnp_decrypt_file(dst, dec, '\n'.join([pswd] * 5))
                remove_files(dec)

            remove_files(dst, dec)

        clear_workfiles()

    def test_encryption_and_signing(self):
        USERIDS = ['enc-sign1@rnp', 'enc-sign2@rnp', 'enc-sign3@rnp']
        KEYPASS = ['encsign1pass', 'encsign2pass', 'encsign3pass']
        PASSWORDS = ['password1', 'password2', 'password3']
        AEAD_C = list_upto(['AES', 'AES192', 'AES256', 'TWOFISH', 'CAMELLIA128', 'CAMELLIA192', 'CAMELLIA256'], Encryption.RUNS)
        # Generate multiple keys and import to GnuPG
        for uid, pswd in zip(USERIDS, KEYPASS):
            rnp_genkey_rsa(uid, 1024, pswd)

        gpg_import_pubring()
        gpg_import_secring()

        SIGNERS = list_upto(range(1, len(USERIDS) + 1), Encryption.RUNS)
        KEYPSWD = tuple((t1, t2) for t1 in range(1, len(USERIDS) + 1) for t2 in range(len(PASSWORDS) + 1))
        KEYPSWD = list_upto(KEYPSWD, Encryption.RUNS)
        if gpg_supports_aead():
            AEADS = list_upto([None, [None], ['eax'], ['ocb']], Encryption.RUNS)
        else:
            AEADS = list_upto([None], Encryption.RUNS)
        ZS = list_upto([None, [None, 0]], Encryption.RUNS)

        src, dst, dec = reg_workfiles('cleartext', '.txt', '.rnp', '.dec')
        # Generate random file of required size
        random_text(src, 128000)

        for i in range(0, Encryption.RUNS):
            signers = USERIDS[:SIGNERS[i]]
            signpswd = KEYPASS[:SIGNERS[i]]
            keynum, pswdnum = KEYPSWD[i]
            recipients = USERIDS[:keynum]
            passwords = PASSWORDS[:pswdnum]
            aead = AEADS[i]
            z = ZS[i]
            cipher = AEAD_C[i]

            rnp_encrypt_and_sign_file(src, dst, recipients, passwords, signers, signpswd, aead, cipher, z)
            # Decrypt file with each of the keys, we have different password for each key
            for pswd in KEYPASS[:keynum]:
                gpg_decrypt_file(dst, dec, pswd)
                gpg_agent_clear_cache()
                remove_files(dec)
                rnp_decrypt_file(dst, dec, '\n'.join([pswd] * 5))

            # GPG decrypts only with first password, see T3795
            if (not aead) and pswdnum:
                gpg_decrypt_file(dst, dec, PASSWORDS[0])
                gpg_agent_clear_cache
                remove_files(dec)

            # Decrypt file with each of the passwords
            for pswd in PASSWORDS[:pswdnum]:
                if aead:
                    gpg_decrypt_file(dst, dec, pswd)
                    gpg_agent_clear_cache()
                    remove_files(dec)
                rnp_decrypt_file(dst, dec, '\n'.join([pswd] * 5))
                remove_files(dec)

            remove_files(dst, dec)


class Compression(unittest.TestCase):

    def setUp(self):
        # Compression is currently implemented only for encrypted messages
        rnp_genkey_rsa(KEY_ENCRYPT)
        rnp_genkey_rsa(KEY_SIGN_GPG)
        gpg_import_pubring()
        gpg_import_secring()

    def tearDown(self):
        clear_keyrings()

    def test_rnp_compression(self):
        levels = [None, 0, 2, 4, 6, 9]
        algosrnp = [None, 'zip', 'zlib', 'bzip2']
        sizes = [20, 1000, 5000, 20000, 150000, 1000000]

        for size in sizes:
            for algo in [0, 1, 2]:
                for level in levels:
                    z = [algosrnp[algo], level]
                    gpg_to_rnp_encryption(size, None, z)
                    file_encryption_rnp_to_gpg(size, z)
                    rnp_signing_gpg_to_rnp(size, z)

class SignDefault(unittest.TestCase):
    '''
        Things to try later:
        - different public key algorithms
        - different hash algorithms where applicable
        - cleartext signing/verification
        - detached signing/verification
    '''
    # Message sizes to be tested
    SIZES = [20, 1000, 5000, 20000, 150000, 1000000]

    @classmethod
    def setUpClass(cls):
        # Generate keypair in RNP
        rnp_genkey_rsa(KEY_SIGN_RNP)
        rnp_genkey_rsa(KEY_SIGN_GPG)
        gpg_import_pubring()
        gpg_import_secring()

    @classmethod
    def tearDownClass(cls):
        clear_keyrings()

    # TODO: This script should generate one test case per message size.
    #       Not sure how to do it yet
    def test_rnp_to_gpg_default_key(self):
        for size in Sign.SIZES:
            rnp_signing_rnp_to_gpg(size)
            rnp_detached_signing_rnp_to_gpg(size)
            rnp_cleartext_signing_rnp_to_gpg(size)

    def test_gpg_to_rnp_default_key(self):
        for size in Sign.SIZES:
            rnp_signing_gpg_to_rnp(size)
            rnp_detached_signing_gpg_to_rnp(size)
            rnp_cleartext_signing_gpg_to_rnp(size)

    def test_rnp_multiple_signers(self):
        USERIDS = ['sign1@rnp', 'sign2@rnp', 'sign3@rnp']
        KEYPASS = ['sign1pass', 'sign2pass', 'sign3pass']

        # Generate multiple keys and import to GnuPG
        for uid, pswd in zip(USERIDS, KEYPASS):
            rnp_genkey_rsa(uid, 1024, pswd)

        gpg_import_pubring()
        gpg_import_secring()

        src, dst, sig, ver = reg_workfiles('cleartext', '.txt', '.rnp', '.txt.sig', '.ver')
        # Generate random file of required size
        random_text(src, 128000)

        for keynum in range(1, len(USERIDS) + 1):
            # Normal signing
            rnp_sign_file(src, dst, USERIDS[:keynum], KEYPASS[:keynum])
            gpg_verify_file(dst, ver)
            remove_files(ver)
            rnp_verify_file(dst, ver)
            remove_files(dst, ver)

            # Detached signing
            rnp_sign_detached(src, USERIDS[:keynum], KEYPASS[:keynum])
            gpg_verify_detached(src, sig)
            rnp_verify_detached(sig)
            remove_files(sig)

            # Cleartext signing
            rnp_sign_cleartext(src, dst, USERIDS[:keynum], KEYPASS[:keynum])
            gpg_verify_cleartext(dst)
            rnp_verify_cleartext(dst)
            remove_files(dst)

        clear_workfiles()


class Encrypt(unittest.TestCase, TestIdMixin, KeyLocationChooserMixin):
    def _encrypt_decrypt(self, e1, e2):
        key_id = "".join(self.id().split('.')[1:3])
        keyfile, input, enc_out, dec_out = reg_workfiles(self.test_id, '.gpg', '.in', '.enc', '.dec')
        random_text(input, 0x1337)

        if not self.operation_key_location and not self.operation_key_gencmd:
            raise RuntimeError("key not found")

        if self.operation_key_location:
            self.assertTrue(e1.import_key(self.operation_key_location[0]))
            self.assertTrue(e1.import_key(self.operation_key_location[1], True))
        else:
            self.assertTrue(e1.generte_key_batch(self.operation_key_gencmd))

        self.assertTrue(e1.export_key(keyfile, False))
        self.assertTrue(e2.import_key(keyfile))
        self.assertTrue(e2.encrypt(e1.userid, enc_out, input))
        self.assertTrue(e1.decrypt(dec_out, enc_out))
        clear_workfiles()

    def setUp(self):
        self.rnp = Rnp(RNPDIR, RNP, RNPK)
        self.gpg = GnuPG(GPGDIR, GPG)
        self.rnp.password = self.gpg.password = PASSWORD
        self.rnp.userid = self.gpg.userid = self.test_id+'@example.com'

    @classmethod
    def tearDownClass(cls):
        clear_keyrings()

class EncryptElgamal(Encrypt):

    GPG_GENERATE_DSA_ELGAMAL_PATTERN = """
        Key-Type: dsa
        Key-Length: {0}
        Key-Usage: sign
        Subkey-Type: ELG-E
        Subkey-Length: {1}
        Subkey-Usage: encrypt
        Name-Real: Test Testovich
        Expire-Date: 1y
        Preferences: twofish sha256 sha384 sha512 sha1 zlib
        Name-Email: {2}
        """

    RNP_GENERATE_DSA_ELGAMAL_PATTERN = "16\n{0}\n"

    @staticmethod
    def key_pfx(sign_key_size, enc_key_size):
        return "GnuPG_dsa_elgamal_%d_%d" % (sign_key_size, enc_key_size)

    def do_test_encrypt(self, sign_key_size, enc_key_size):
        pfx = EncryptElgamal.key_pfx(sign_key_size, enc_key_size)
        self.operation_key_location = tuple((key_path(pfx,False), key_path(pfx,True)))
        self.rnp.userid = self.gpg.userid = pfx+"@example.com"
        self._encrypt_decrypt(self.gpg, self.rnp)

    def do_test_decrypt(self, sign_key_size, enc_key_size):
        pfx = EncryptElgamal.key_pfx(sign_key_size, enc_key_size)
        self.operation_key_location = tuple((key_path(pfx,False), key_path(pfx,True)))
        self.rnp.userid = self.gpg.userid = pfx+"@example.com"
        self._encrypt_decrypt(self.rnp, self.gpg)

    def test_encrypt_P1024_1024(self): self.do_test_encrypt(1024, 1024)
    def test_encrypt_P1024_2048(self): self.do_test_encrypt(1024, 2048)
    def test_encrypt_P2048_2048(self): self.do_test_encrypt(2048, 2048)
    def test_encrypt_P3072_3072(self): self.do_test_encrypt(3072, 3072)
    def test_decrypt_P1024_1024(self): self.do_test_decrypt(1024, 1024)
    def test_decrypt_P2048_2048(self): self.do_test_decrypt(2048, 2048)
    def test_decrypt_P1234_1234(self): self.do_test_decrypt(1234, 1234)

    def test_generate_elgamal_key1024_in_gpg_and_encrypt(self):
        cmd = EncryptElgamal.GPG_GENERATE_DSA_ELGAMAL_PATTERN.format(1024, 1024, self.gpg.userid)
        self.operation_key_gencmd = cmd
        self._encrypt_decrypt(self.gpg, self.rnp)

    def test_generate_elgamal_key1024_in_rnp_and_decrypt(self):
        cmd = EncryptElgamal.RNP_GENERATE_DSA_ELGAMAL_PATTERN.format(1024)
        self.operation_key_gencmd = cmd
        self._encrypt_decrypt(self.rnp, self.gpg)


class EncryptEcdh(Encrypt):

    GPG_GENERATE_ECDH_ECDSA_PATTERN = """
        Key-Type: ecdsa
        Key-Curve: {0}
        Key-Usage: sign auth
        Subkey-Type: ecdh
        Subkey-Usage: encrypt
        Subkey-Curve: {0}
        Name-Real: Test Testovich
        Expire-Date: 1y
        Preferences: twofish sha256 sha384 sha512 sha1 zlib
        Name-Email: {1}"""

    RNP_GENERATE_ECDH_ECDSA_PATTERN = "19\n{0}\n"

    def test_encrypt_nistP256(self):
        self.operation_key_gencmd = EncryptEcdh.GPG_GENERATE_ECDH_ECDSA_PATTERN.format("nistp256", self.rnp.userid)
        self._encrypt_decrypt(self.gpg, self.rnp)

    def test_encrypt_nistP384(self):
        self.operation_key_gencmd = EncryptEcdh.GPG_GENERATE_ECDH_ECDSA_PATTERN.format("nistp384", self.rnp.userid)
        self._encrypt_decrypt(self.gpg, self.rnp)

    def test_encrypt_nistP521(self):
        self.operation_key_gencmd = EncryptEcdh.GPG_GENERATE_ECDH_ECDSA_PATTERN.format("nistp521", self.rnp.userid)
        self._encrypt_decrypt(self.gpg, self.rnp)

    def test_decrypt_nistP256(self):
        self.operation_key_gencmd = EncryptEcdh.RNP_GENERATE_ECDH_ECDSA_PATTERN.format(1)
        self._encrypt_decrypt(self.rnp, self.gpg)

    def test_decrypt_nistP384(self):
        self.operation_key_gencmd = EncryptEcdh.RNP_GENERATE_ECDH_ECDSA_PATTERN.format(2)
        self._encrypt_decrypt(self.rnp, self.gpg)

    def test_decrypt_nistP521(self):
        self.operation_key_gencmd = EncryptEcdh.RNP_GENERATE_ECDH_ECDSA_PATTERN.format(3)
        self._encrypt_decrypt(self.rnp, self.gpg)

class Sign(unittest.TestCase, TestIdMixin, KeyLocationChooserMixin):
    SIZES = [20, 1000, 5000, 20000, 150000, 1000000]

    def _sign_verify(self, e1, e2):
        '''
        Helper function for Sign verification
        1. e1 creates/loads key
        2. e1 exports key
        3. e2 imports key
        2. e1 signs message
        3. e2 verifies message

        eX == entityX
        '''
        keyfile, input, output = reg_workfiles(self.test_id, '.gpg', '.in', '.out')
        random_text(input, 0x1337)

        if not self.operation_key_location and not self.operation_key_gencmd:
            print(self.operation_key_gencmd)
            raise RuntimeError("key not found")

        if self.operation_key_location:
            self.assertTrue(e1.import_key(self.operation_key_location[0]))
            self.assertTrue(e1.import_key(self.operation_key_location[1], True))
        else:
            self.assertTrue(e1.generte_key_batch(self.operation_key_gencmd))
        self.assertTrue(e1.export_key(keyfile, False))
        self.assertTrue(e2.import_key(keyfile))
        self.assertTrue(e1.sign(output, input))
        self.assertTrue(e2.verify(output))
        clear_workfiles()

    def setUp(self):
        self.rnp = Rnp(RNPDIR, RNP, RNPK)
        self.gpg = GnuPG(GPGDIR, GPG)
        self.rnp.password = self.gpg.password = PASSWORD
        self.rnp.userid = self.gpg.userid = self.test_id+'@example.com'

    @classmethod
    def tearDownClass(cls):
        clear_keyrings()

class SignECDSA(Sign):
    # {0} must be replaced by ID of the curve 3,4 or 5 (NIST-256,384,521)
    #CURVES = ["NIST P-256", "NIST P-384", "NIST P-521"]
    GPG_GENERATE_ECDSA_PATTERN = """
        Key-Type: ecdsa
        Key-Curve: {0}
        Key-Usage: sign auth
        Name-Real: Test Testovich
        Expire-Date: 1y
        Preferences: twofish sha512 zlib
        Name-Email: {1}"""

    # {0} must be replaced by ID of the curve 1,2 or 3 (NIST-256,384,521)
    RNP_GENERATE_ECDSA_PATTERN = "19\n{0}\n"

    def test_sign_P256(self):
        cmd = SignECDSA.RNP_GENERATE_ECDSA_PATTERN.format(1)
        self.operation_key_gencmd = cmd
        self._sign_verify(self.rnp, self.gpg)

    def test_sign_P384(self):
        cmd = SignECDSA.RNP_GENERATE_ECDSA_PATTERN.format(2)
        self.operation_key_gencmd = cmd
        self._sign_verify(self.rnp, self.gpg)

    def test_sign_P521(self):
        cmd = SignECDSA.RNP_GENERATE_ECDSA_PATTERN.format(3)
        self.operation_key_gencmd = cmd
        self._sign_verify(self.rnp, self.gpg)

    def test_verify_P256(self):
        cmd = SignECDSA.GPG_GENERATE_ECDSA_PATTERN.format("nistp256", self.rnp.userid)
        self.operation_key_gencmd = cmd
        self._sign_verify(self.gpg, self.rnp)

    def test_verify_P384(self):
        cmd = SignECDSA.GPG_GENERATE_ECDSA_PATTERN.format("nistp384", self.rnp.userid)
        self.operation_key_gencmd = cmd
        self._sign_verify(self.gpg, self.rnp)

    def test_verify_P521(self):
        cmd = SignECDSA.GPG_GENERATE_ECDSA_PATTERN.format("nistp521", self.rnp.userid)
        self.operation_key_gencmd = cmd
        self._sign_verify(self.gpg, self.rnp)

    def test_hash_truncation(self):
        '''
        Signs message hashed with SHA512 with a key of size 256. Implementation
        truncates leftmost 256 bits of a hash before signing (see FIPS 186-4, 6.4)
        '''
        cmd = SignECDSA.RNP_GENERATE_ECDSA_PATTERN.format(1)
        rnp = self.rnp.copy()
        rnp.hash = 'SHA512'
        self.operation_key_gencmd = cmd
        self._sign_verify(rnp, self.gpg)

class SignDSA(Sign):
    # {0} must be replaced by ID of the curve 3,4 or 5 (NIST-256,384,521)
    #CURVES = ["NIST P-256", "NIST P-384", "NIST P-521"]
    GPG_GENERATE_DSA_PATTERN = """
        Key-Type: dsa
        Key-Length: {0}
        Key-Usage: sign auth
        Name-Real: Test Testovich
        Expire-Date: 1y
        Preferences: twofish sha256 sha384 sha512 sha1 zlib
        Name-Email: {1}"""

    # {0} must be replaced by ID of the curve 1,2 or 3 (NIST-256,384,521)
    RNP_GENERATE_DSA_PATTERN = "17\n{0}\n"

    @staticmethod
    def key_pfx(p): return "GnuPG_dsa_elgamal_%d_%d" % (p,p)

    def do_test_sign(self, p_size):
        pfx = SignDSA.key_pfx(p_size)
        self.operation_key_location = tuple((key_path(pfx,False), key_path(pfx,True)))
        self.rnp.userid = self.gpg.userid = pfx+"@example.com"
        self._sign_verify(self.rnp, self.gpg)

    def do_test_verify(self, p_size):
        pfx = SignDSA.key_pfx(p_size)
        self.operation_key_location = tuple((key_path(pfx,False), key_path(pfx,True)))
        self.rnp.userid = self.gpg.userid = pfx+"@example.com"
        self._sign_verify(self.gpg, self.rnp)

    def test_sign_P1024_Q160(self): self.do_test_sign(1024)
    def test_sign_P2048_Q256(self): self.do_test_sign(2048)
    def test_sign_P3072_Q256(self): self.do_test_sign(3072)
    def test_sign_P2112_Q256(self): self.do_test_sign(2112)

    def test_verify_P1024_Q160(self): self.do_test_verify(1024)
    def test_verify_P2048_Q256(self): self.do_test_verify(2048)
    def test_verify_P3072_Q256(self): self.do_test_verify(3072)
    def test_verify_P2112_Q256(self): self.do_test_verify(2112)

    def test_sign_P1088_Q224(self):
        self.operation_key_gencmd = SignDSA.RNP_GENERATE_DSA_PATTERN.format(1088)
        self._sign_verify(self.rnp, self.gpg)

    def test_verify_P1088_Q224(self):
        self.operation_key_gencmd = SignDSA.GPG_GENERATE_DSA_PATTERN.format("1088", self.rnp.userid)
        self._sign_verify(self.gpg, self.rnp)

    def test_hash_truncation(self):
        '''
        Signs message hashed with SHA512 with a key of size 160 bits. Implementation
        truncates leftmost 160 bits of a hash before signing (see FIPS 186-4, 4.2)
        '''
        rnp = self.rnp.copy()
        rnp.hash = 'SHA512'
        self.operation_key_gencmd = SignDSA.RNP_GENERATE_DSA_PATTERN.format(1024)
        self._sign_verify(rnp, self.gpg)

class EncryptSignRSA(Encrypt, Sign):

    GPG_GENERATE_RSA_PATTERN = """
        Key-Type: rsa
        Key-Length: {0}
        Key-Usage: sign auth
        Subkey-Type: rsa
        Subkey-Length: {0}
        Subkey-Usage: encrypt
        Name-Real: Test Testovich
        Expire-Date: 1y
        Preferences: twofish sha256 sha384 sha512 sha1 zlib
        Name-Email: {1}"""

    RNP_GENERATE_RSA_PATTERN = "1\n{0}\n"

    @staticmethod
    def key_pfx(p): return "GnuPG_rsa_%d_%d" % (p,p)

    def do_encrypt_verify(self, key_size):
        pfx = EncryptSignRSA.key_pfx(key_size)
        self.operation_key_location = tuple((key_path(pfx,False), key_path(pfx,True)))
        self.rnp.userid = self.gpg.userid = pfx+"@example.com"
        self._encrypt_decrypt(self.gpg, self.rnp)
        self._sign_verify(self.gpg, self.rnp)

    def do_rnp_decrypt_sign(self, key_size):
        pfx = EncryptSignRSA.key_pfx(key_size)
        self.operation_key_location = tuple((key_path(pfx,False), key_path(pfx,True)))
        self.rnp.userid = self.gpg.userid = pfx+"@example.com"
        self._encrypt_decrypt(self.rnp, self.gpg)
        self._sign_verify(self.rnp, self.gpg)

    def test_rnp_encrypt_verify_1024(self): self.do_encrypt_verify(1024)
    def test_rnp_encrypt_verify_2048(self): self.do_encrypt_verify(2048)
    def test_rnp_encrypt_verify_4096(self): self.do_encrypt_verify(4096)

    def test_rnp_decrypt_sign_1024(self): self.do_rnp_decrypt_sign(1024)
    def test_rnp_decrypt_sign_2048(self): self.do_rnp_decrypt_sign(2048)
    def test_rnp_decrypt_sign_4096(self): self.do_rnp_decrypt_sign(4096)

def test_suites(tests):
    if hasattr(tests, '__iter__'):
        for x in tests:
            for y in test_suites(x):
                yield y
    else:
        yield tests.__class__.__name__

# Main thinghy

if __name__ == '__main__':
    main = unittest.main
    main.USAGE +=   ''.join([
                    "\nRNP test client specific flags:\n",
                    "  -w,\t\t Don't remove working directory\n",
                    "  -d,\t\t Enable debug messages\n"])

    LEAVE_WORKING_DIRECTORY = ("-w" in sys.argv)
    if LEAVE_WORKING_DIRECTORY:
        # -w must be removed as unittest doesn't expect it
        sys.argv.remove('-w')

    LVL = logging.INFO
    if "-d" in sys.argv:
        sys.argv.remove('-d')
        LVL = logging.DEBUG

    # list suites
    if '-ls' in sys.argv:
        tests = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
        for suite in set(test_suites(tests)):
            print(suite)
        sys.exit(0)

    setup(LVL)
    main()

    if not LEAVE_WORKING_DIRECTORY:
        try:
            if RMWORKDIR:
                shutil.rmtree(WORKDIR)
            else:
                shutil.rmtree(RNPDIR)
                shutil.rmtree(GPGDIR)
        except:
            pass
