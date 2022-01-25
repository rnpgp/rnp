#!/usr/bin/env python

import logging
import os
import os.path
import re
import shutil
import sys
import tempfile
import time
import unittest
from platform import architecture

import cli_common
from cli_common import (file_text, find_utility, is_windows, list_upto,
                        path_for_gpg, pswd_pipe, raise_err, random_text,
                        run_proc, decode_string_escape, CONSOLE_ENCODING)
from gnupg import GnuPG as GnuPG
from rnp import Rnp as Rnp

WORKDIR = ''
RNP = ''
RNPK = ''
GPG = ''
GPGCONF = ''
RNPDIR = ''
GPGHOME = None
PASSWORD = 'password'
RMWORKDIR = True
GPG_AEAD = False
GPG_NO_OLD = False
TESTS_SUCCEEDED = []
TESTS_FAILED = []
TEST_WORKFILES = []

# Supported features
RNP_TWOFISH = True
RNP_BRAINPOOL = True
RNP_AEAD = True

if sys.version_info >= (3,):
    unichr = chr

def escape_regex(str):
    return '^' + ''.join((c, "[\\x{:02X}]".format(ord(c)))[0 <= ord(c) <= 0x20 \
        or c in ['[',']','(',')','|','"','$','.','*','^','$','\\','+','?','{','}']] for c in str) + '$'

UNICODE_LATIN_CAPITAL_A_GRAVE = unichr(192)
UNICODE_LATIN_SMALL_A_GRAVE = unichr(224)
UNICODE_LATIN_CAPITAL_A_MACRON = unichr(256)
UNICODE_LATIN_SMALL_A_MACRON = unichr(257)
UNICODE_GREEK_CAPITAL_HETA = unichr(880)
UNICODE_GREEK_SMALL_HETA = unichr(881)
UNICODE_GREEK_CAPITAL_OMEGA = unichr(937)
UNICODE_GREEK_SMALL_OMEGA = unichr(969)
UNICODE_CYRILLIC_CAPITAL_A = unichr(0x0410)
UNICODE_CYRILLIC_SMALL_A = unichr(0x0430)
UNICODE_CYRILLIC_CAPITAL_YA = unichr(0x042F)
UNICODE_CYRILLIC_SMALL_YA = unichr(0x044F)
UNICODE_SEQUENCE_1 = UNICODE_LATIN_CAPITAL_A_GRAVE + UNICODE_LATIN_SMALL_A_MACRON \
    + UNICODE_GREEK_CAPITAL_HETA + UNICODE_GREEK_SMALL_OMEGA \
    + UNICODE_CYRILLIC_CAPITAL_A + UNICODE_CYRILLIC_SMALL_YA
UNICODE_SEQUENCE_2 = UNICODE_LATIN_SMALL_A_GRAVE + UNICODE_LATIN_CAPITAL_A_MACRON \
    + UNICODE_GREEK_SMALL_HETA + UNICODE_GREEK_CAPITAL_OMEGA \
    + UNICODE_CYRILLIC_SMALL_A + UNICODE_CYRILLIC_CAPITAL_YA
WEIRD_USERID_UNICODE_1 = unichr(160) + unichr(161) \
    + UNICODE_SEQUENCE_1 + unichr(40960) + u'@rnp'
WEIRD_USERID_UNICODE_2 = unichr(160) + unichr(161) \
    + UNICODE_SEQUENCE_2 + unichr(40960) + u'@rnp'
WEIRD_USERID_SPECIAL_CHARS = '\\}{][)^*.+(\t\n|$@rnp'
WEIRD_USERID_SPACE = ' '
WEIRD_USERID_QUOTE = '"'
WEIRD_USERID_SPACE_AND_QUOTE = ' "'
WEIRD_USERID_QUOTE_AND_SPACE = '" '
WEIRD_USERID_TOO_LONG = 'x' * 125 + '@rnp' # totaling 129 (MAX_USER_ID + 1)

# Key userids
KEY_ENCRYPT = 'encryption@rnp'
KEY_SIGN_RNP = 'signing@rnp'
KEY_SIGN_GPG = 'signing@gpg'
KEY_ENC_RNP = 'enc@rnp'
AT_EXAMPLE = '@example.com'

# Keyrings
PUBRING = 'pubring.gpg'
SECRING = 'secring.gpg'
PUBRING_1 = 'keyrings/1/pubring.gpg'
SECRING_G10 = 'test_stream_key_load/g10'
KEY_ALICE_PUB = 'test_key_validity/alice-pub.asc'
KEY_ALICE_SEC = 'test_key_validity/alice-sec.asc'
KEY_ALICE_SUB_SEC = 'test_key_validity/alice-sub-sec.pgp'
KEY_25519_NOTWEAK_SEC = 'test_key_edge_cases/key-25519-non-tweaked-sec.asc'

# Messages
MSG_TXT = 'test_messages/message.txt'
MSG_ES_25519 = 'test_messages/message.txt.enc-sign-25519'

# Extensions
EXT_SIG = '.txt.sig'
EXT_ASC = '.txt.asc'
EXT_PGP = '.txt.pgp'

# Misc
GPG_LOOPBACK = '--pinentry-mode=loopback'

# Regexps
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

RE_RNP_ENCRYPTED_KEY = r'(?s)^.*' \
r'Secret key packet.*' \
r'secret key material:.*' \
r'encrypted secret key data:.*' \
r'UserID packet.*' \
r'id: enc@rnp.*' \
r'Secret subkey packet.*' \
r'secret key material:.*' \
r'encrypted secret key data:.*$'

RE_RNP_REVOCATION_SIG = r'(?s)^.*' \
r'packet header .* \(tag 2, len .*' \
r'Signature packet.*' \
r'version: 4.*' \
r'type: 32 \(Key revocation signature\).*' \
r'public key algorithm:.*' \
r'hashed subpackets:.*' \
r':type 33, len 21.*' \
r'issuer fingerprint:.*' \
r':type 2, len 4.*' \
r'signature creation time:.*' \
r':type 29.*' \
r'reason for revocation: (.*)' \
r'message: (.*)' \
r'unhashed subpackets:.*' \
r':type 16, len 8.*' \
r'issuer key ID: .*$'

RE_GPG_REVOCATION_IMPORT = r'(?s)^.*' \
r'key 0451409669FFDE3C: "Alice <alice@rnp>" revocation certificate imported.*' \
r'Total number processed: 1.*' \
r'new key revocations: 1.*$'

RE_SIG_1_IMPORT = r'(?s)^.*Import finished: 1 new signature, 0 unchanged, 0 unknown.*'

RNP_TO_GPG_ZALGS = { 'zip' : '1', 'zlib' : '2', 'bzip2' : '3' }
# These are mostly identical
RNP_TO_GPG_CIPHERS = {'AES' : 'aes128', 'AES192' : 'aes192', 'AES256' : 'aes256',
                      'TWOFISH' : 'twofish', 'CAMELLIA128' : 'camellia128',
                      'CAMELLIA192' : 'camellia192', 'CAMELLIA256' : 'camellia256',
                      'IDEA' : 'idea', '3DES' : '3des', 'CAST5' : 'cast5',
                      'BLOWFISH' : 'blowfish'}

# Error messages
RNP_DATA_DIFFERS = 'rnp decrypted data differs'
GPG_DATA_DIFFERS = 'gpg decrypted data differs'
KEY_GEN_FAILED = 'key generation failed'
KEY_LIST_FAILED = 'key list failed'
KEY_LIST_WRONG = 'wrong key list output'
PKT_LIST_FAILED = 'packet listing failed'
ALICE_IMPORT_FAIL = 'Alice key import failed'
ENC_FAILED = 'encryption failed'
DEC_FAILED = 'decryption failed'
DEC_DIFFERS = 'Decrypted data differs'

def check_packets(fname, regexp):
    ret, output, err = run_proc(GPG, ['--homedir', '.',
                                      '--list-packets', path_for_gpg(fname)])
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
    os.mkdir(RNPDIR, 0o700)

    run_proc(GPGCONF, ['--homedir', GPGHOME, '--kill', 'gpg-agent'])
    while os.path.isdir(GPGDIR):
        try:
            shutil.rmtree(GPGDIR)
        except Exception:
            time.sleep(0.1)
    os.mkdir(GPGDIR, 0o700)

def allow_y2k38_on_32bit(filename):
    if architecture()[0] == '32bit':
        return [filename, filename + '_y2k38']
    else:
        return [filename]

def compare_files(src, dst, message):
    if file_text(src) != file_text(dst):
        raise_err(message)

def compare_file(src, string, message):
    if file_text(src) != string:
        raise_err(message)

def compare_file_any(srcs, string, message):
    for src in srcs:
        if file_text(src) == string:
            return
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
    except Exception:
        pass

def reg_workfiles(mainname, *exts):
    global TEST_WORKFILES
    res = []
    for ext in exts:
        fpath = os.path.join(WORKDIR, mainname + ext)
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
        except (OSError):
            pass
    TEST_WORKFILES = []


def rnp_genkey_rsa(userid, bits=2048, pswd=PASSWORD):
    pipe = pswd_pipe(pswd)
    ret, _, err = run_proc(RNPK, ['--numbits', str(bits), '--homedir', RNPDIR, '--pass-fd', str(pipe),
                                  '--notty', '--s2k-iterations', '50000', '--userid', userid, '--generate-key'])
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

def rnp_encrypt_file_ex(src, dst, recipients=None, passwords=None, aead=None, cipher=None,
                        z=None, armor=False):
    params = ['--homedir', RNPDIR, src, '--output', dst]
    # Recipients. None disables PK encryption, [] to use default key. Otherwise list of ids.
    if recipients != None:
        params[2:2] = ['--encrypt']
        for userid in reversed(recipients):
            params[2:2] = ['-r', escape_regex(userid)]
    # Passwords to encrypt to. None or [] disables password encryption.
    if passwords:
        if recipients is None:
            params[2:2] = ['-c']
        pipe = pswd_pipe('\n'.join(passwords))
        params[2:2] = ['--pass-fd', str(pipe), '--passwords', str(len(passwords))]

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

def rnp_encrypt_and_sign_file(src, dst, recipients, encrpswd, signers, signpswd,
                              aead=None, cipher=None, z=None, armor=False):
    params = ['--homedir', RNPDIR, '--sign', '--encrypt', src, '--output', dst]
    pipe = pswd_pipe('\n'.join(encrpswd + signpswd))
    params[2:2] = ['--pass-fd', str(pipe)]

    # Encrypting passwords if any
    if encrpswd:
        params[2:2] = ['--passwords', str(len(encrpswd))]
    # Adding recipients. If list is empty then default will be used.
    for userid in reversed(recipients):
        params[2:2] = ['-r', escape_regex(userid)]
    # Adding signers. If list is empty then default will be used.
    for signer in reversed(signers):
        params[2:2] = ['-u', escape_regex(signer)]
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
        params[4:4] = ['--userid', escape_regex(signer)]

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
        kpath = os.path.join(RNPDIR, PUBRING)
    ret, _, err = run_proc(
        GPG, ['--display-charset', CONSOLE_ENCODING, '--batch', '--homedir', GPGHOME, '--import', kpath])
    if ret != 0:
        raise_err('gpg key import failed', err)


def gpg_import_secring(kpath=None, password = PASSWORD):
    if not kpath:
        kpath = os.path.join(RNPDIR, SECRING)
    ret, _, err = run_proc(
        GPG, ['--display-charset', CONSOLE_ENCODING, '--batch', '--passphrase', password, '--homedir', GPGHOME, '--import', kpath])
    if ret != 0:
        raise_err('gpg secret key import failed', err)


def gpg_export_secret_key(userid, password, keyfile):
    ret, _, err = run_proc(GPG, ['--batch', '--homedir', GPGHOME, GPG_LOOPBACK,
                                 '--yes', '--passphrase', password, '--output',
                                 path_for_gpg(keyfile), '--export-secret-key', userid])

    if ret != 0:
        raise_err('gpg secret key export failed', err)

def gpg_params_insert_z(params, pos, z):
    if z:
        if len(z) > 0 and z[0] != None:
            params[pos:pos] = ['--compress-algo', RNP_TO_GPG_ZALGS[z[0]]]
        if len(z) > 1 and z[1] != None:
            params[pos:pos] = ['-z', str(z[1])]

def gpg_encrypt_file(src, dst, cipher=None, z=None, armor=False):
    src = path_for_gpg(src)
    dst = path_for_gpg(dst)
    params = ['--homedir', GPGHOME, '-e', '-r', KEY_ENCRYPT, '--batch',
              '--trust-model', 'always', '--output', dst, src]
    if z: gpg_params_insert_z(params, 3, z)
    if cipher: params[3:3] = ['--cipher-algo', RNP_TO_GPG_CIPHERS[cipher]]
    if armor: params[2:2] = ['--armor']
    if GPG_NO_OLD: params[2:2] = ['--allow-old-cipher-algos']

    ret, out, err = run_proc(GPG, params)
    if ret != 0:
        raise_err('gpg encryption failed for cipher ' + cipher, err)

def gpg_symencrypt_file(src, dst, cipher=None, z=None, armor=False, aead=None):
    src = path_for_gpg(src)
    dst = path_for_gpg(dst)
    params = ['--homedir', GPGHOME, '-c', '--s2k-count', '65536', '--batch',
              '--passphrase', PASSWORD, '--output', dst, src]
    if z: gpg_params_insert_z(params, 3, z)
    if cipher: params[3:3] = ['--cipher-algo', RNP_TO_GPG_CIPHERS[cipher]]
    if GPG_NO_OLD: params[3:3] = ['--allow-old-cipher-algos']
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
    src = path_for_gpg(src)
    dst = path_for_gpg(dst)
    ret, out, err = run_proc(GPG, ['--display-charset', CONSOLE_ENCODING, '--homedir', GPGHOME, GPG_LOOPBACK, '--batch',
                                   '--yes', '--passphrase', keypass, '--trust-model',
                                   'always', '-o', dst, '-d', src])
    if ret != 0:
        raise_err('gpg decryption failed', err)


def gpg_verify_file(src, dst, signer=None):
    src = path_for_gpg(src)
    dst = path_for_gpg(dst)
    ret, out, err = run_proc(GPG, ['--display-charset', CONSOLE_ENCODING, '--homedir', GPGHOME, '--batch',
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
    src = path_for_gpg(src)
    sig = path_for_gpg(sig)
    ret, _, err = run_proc(GPG, ['--display-charset', CONSOLE_ENCODING, '--homedir', GPGHOME, '--batch', '--yes', '--trust-model', 
                                 'always', '--verify', sig, src])
    if ret != 0:
        raise_err('gpg detached verification failed', err)
    # Check GPG output
    match = re.match(RE_GPG_GOOD_SIGNATURE, err)
    if not match:
        raise_err('wrong gpg detached verification output', err)
    if signer and (not match.group(1) == signer):
        raise_err('gpg detached verification failed, wrong signer')


def gpg_verify_cleartext(src, signer=None):
    src = path_for_gpg(src)
    ret, _, err = run_proc(
        GPG, ['--display-charset', CONSOLE_ENCODING, '--homedir', GPGHOME, '--batch', '--yes', '--trust-model', 'always', '--verify', src])
    if ret != 0:
        raise_err('gpg cleartext verification failed', err)
    # Check GPG output
    match = re.match(RE_GPG_GOOD_SIGNATURE, err)
    if not match:
        raise_err('wrong gpg verification output', err)
    if signer and (not match.group(1) == signer):
        raise_err('gpg verification failed, wrong signer')


def gpg_sign_file(src, dst, signer, z=None, armor=False):
    src = path_for_gpg(src)
    dst = path_for_gpg(dst)
    params = ['--homedir', GPGHOME, GPG_LOOPBACK, '--batch', '--yes',
              '--passphrase', PASSWORD, '--trust-model', 'always', '-u', signer, '-o',
              dst, '-s', src]
    if z: gpg_params_insert_z(params, 3, z)
    if armor: params.insert(2, '--armor')
    ret, _, err = run_proc(GPG, params)
    if ret != 0:
        raise_err('gpg signing failed', err)


def gpg_sign_detached(src, signer, armor=False, textsig=False):
    src = path_for_gpg(src)
    params = ['--homedir', GPGHOME, GPG_LOOPBACK, '--batch', '--yes',
              '--passphrase', PASSWORD, '--trust-model', 'always', '-u', signer,
              '--detach-sign', src]
    if armor: params.insert(2, '--armor')
    if textsig: params.insert(2, '--text')
    ret, _, err = run_proc(GPG, params)
    if ret != 0:
        raise_err('gpg detached signing failed', err)


def gpg_sign_cleartext(src, dst, signer):
    src = path_for_gpg(src)
    dst = path_for_gpg(dst)
    params = ['--homedir', GPGHOME, GPG_LOOPBACK, '--batch', '--yes', '--passphrase',
              PASSWORD, '--trust-model', 'always', '-u', signer, '-o', dst, '--clearsign', src]
    ret, _, err = run_proc(GPG, params)
    if ret != 0:
        raise_err('gpg cleartext signing failed', err)


def gpg_agent_clear_cache():
    run_proc(GPGCONF, ['--homedir', GPGHOME, '--kill', 'gpg-agent'])

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
        compare_files(src, dec, RNP_DATA_DIFFERS)
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
        compare_files(src, dst, GPG_DATA_DIFFERS)
        remove_files(dst)
        # Decrypt encrypted file with RNP
        rnp_decrypt_file(enc, dst)
        compare_files(src, dst, RNP_DATA_DIFFERS)
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
        compare_files(src, dec, RNP_DATA_DIFFERS)
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
        compare_files(src, dst, GPG_DATA_DIFFERS)
        remove_files(dst)
        # Decrypt encrypted file with RNP
        rnp_decrypt_file(enc, dst)
        compare_files(src, dst, RNP_DATA_DIFFERS)
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
    compare_files(src, dst, RNP_DATA_DIFFERS)
    remove_files(dst)

    if usegpg:
        # Decrypt encrypted file with GPG
        gpg_decrypt_file(enc, dst, PASSWORD)
        compare_files(src, dst, GPG_DATA_DIFFERS)
        remove_files(dst, enc)
        # Encrypt cleartext file with GPG
        gpg_symencrypt_file(src, enc, cipher, z, False, aead)
        # Decrypt encrypted file with RNP
        rnp_decrypt_file(enc, dst)
        compare_files(src, dst, RNP_DATA_DIFFERS)

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
    src, sig, asc = reg_workfiles('cleartext', '.txt', EXT_SIG, EXT_ASC)
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
    src, asc = reg_workfiles('cleartext', '.txt', EXT_ASC)
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


def rnp_detached_signing_gpg_to_rnp(filesize, textsig=False):
    src, sig, asc = reg_workfiles('cleartext', '.txt', EXT_SIG, EXT_ASC)
    # Generate random file of required size
    random_text(src, filesize)
    for armor in [True, False]:
        # Sign file with GPG
        gpg_sign_detached(src, KEY_SIGN_GPG, armor, textsig)
        sigpath = asc if armor else sig
        # Verify file with RNP
        rnp_verify_detached(sigpath, KEY_SIGN_GPG)
    clear_workfiles()

def rnp_cleartext_signing_gpg_to_rnp(filesize):
    src, asc = reg_workfiles('cleartext', '.txt', EXT_ASC)
    # Generate random file of required size
    random_text(src, filesize)
    # Sign file with GPG
    gpg_sign_cleartext(src, asc, KEY_SIGN_GPG)
    # Verify signature with RNP
    rnp_verify_cleartext(asc, KEY_SIGN_GPG)
    # Verify signed message with GPG
    gpg_verify_cleartext(asc, KEY_SIGN_GPG)
    clear_workfiles()

def gpg_check_features():
    global GPG_AEAD, GPG_NO_OLD
    _, out, _ = run_proc(GPG, ["--version"])
    # AEAD
    GPG_AEAD = re.match(r'(?s)^.*AEAD:\s+EAX,\s+OCB.*', out)
    # Version 2.3.0-beta1598 and up drops support of 64-bit block algos
    match = re.match(r'(?s)^.*gpg \(GnuPG\) ([0-9]+)\.([0-9]+)\.([0-9]+)(-beta([0-9]+))?.*$', out)
    if not match:
        raise_err('Failed to parse GnuPG version.')
    # Version < 2.3.0
    if (int(match.group(1)) < 2) or ((int(match.group(1)) == 2) and (int(match.group(2)) < 3)):
        GPG_NO_OLD = False
        return
    # Version > 2.3.0
    if (int(match.group(1)) > 2) or (int(match.group(2)) > 3) or (int(match.group(3)) > 0):
        GPG_NO_OLD = True
        return
    # Version 2.3.0 release or beta
    GPG_NO_OLD = not match.group(5) or (int(match.group(5)) >= 1598)

def rnp_check_features():
    global RNP_TWOFISH, RNP_BRAINPOOL, RNP_AEAD
    ret, out, _ = run_proc(RNP, ['--version'])
    if ret != 0:
        raise_err('Failed to get RNP version.')
    # AEAD
    RNP_AEAD = re.match(r'(?s)^.*AEAD:.*EAX,.*OCB.*', out)
    # Twofish
    RNP_TWOFISH = re.match(r'(?s)^.*Encryption:.*TWOFISH.*', out)
    # Brainpool curves
    RNP_BRAINPOOL = re.match(r'(?s)^.*Curves:.*brainpoolP256r1.*brainpoolP384r1.*brainpoolP512r1.*', out)
    # Check that everything is enabled for Botan:
    if re.match(r'(?s)^.*Backend:\s+Botan.*', out) and (not RNP_AEAD or not RNP_TWOFISH or not RNP_BRAINPOOL):
        raise_err('Something is wrong with features detection.')

def setup(loglvl):
    # Setting up directories.
    global RMWORKDIR, WORKDIR, RNPDIR, RNP, RNPK, GPG, GPGDIR, GPGHOME, GPGCONF
    logging.basicConfig(stream=sys.stderr, format="%(message)s")
    logging.getLogger().setLevel(loglvl)
    WORKDIR = tempfile.mkdtemp(prefix='rnpctmp')
    RMWORKDIR = True

    logging.info('Running in ' + WORKDIR)

    cli_common.WORKDIR = WORKDIR
    RNPDIR = os.path.join(WORKDIR, '.rnp')
    RNP = os.getenv('RNP_TESTS_RNP_PATH') or 'rnp'
    RNPK = os.getenv('RNP_TESTS_RNPKEYS_PATH') or 'rnpkeys'
    shutil.rmtree(RNPDIR, ignore_errors=True)
    os.mkdir(RNPDIR, 0o700)

    os.environ["RNP_LOG_CONSOLE"] = "1"

    GPGDIR = os.path.join(WORKDIR, '.gpg')
    GPGHOME = path_for_gpg(GPGDIR) if is_windows() else GPGDIR
    GPG = os.getenv('RNP_TESTS_GPG_PATH') or find_utility('gpg')
    GPGCONF = os.getenv('RNP_TESTS_GPGCONF_PATH') or find_utility('gpgconf')
    gpg_check_features()
    rnp_check_features()
    shutil.rmtree(GPGDIR, ignore_errors=True)
    os.mkdir(GPGDIR, 0o700)

def data_path(subpath):
    ''' Constructs path to the tests data file/dir'''
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', subpath)

def key_path(file_base_name, secret):
    ''' Constructs path to the .gpg file'''
    path=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/cli_EncryptSign',
                      file_base_name)
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

    @classmethod
    def tearDownClass(cls):
        clear_keyrings()

    def tearDown(self):
        clear_workfiles()

    def _rnpkey_generate_rsa(self, bits= None):
        # Setup command line params
        if bits:
            params = ['--numbits', str(bits)]
        else:
            params = []
            bits = 2048

        userid = str(bits) + '@rnptest'
        # Open pipe for password
        pipe = pswd_pipe(PASSWORD)
        params = params + ['--homedir', RNPDIR, '--pass-fd', str(pipe), 
                           '--userid', userid, '--s2k-iterations', '50000', '--generate-key']
        # Run key generation
        ret, _, _ = run_proc(RNPK, params)
        os.close(pipe)
        self.assertEqual(ret, 0, KEY_GEN_FAILED)
        # Check packets using the gpg
        match = check_packets(os.path.join(RNPDIR, PUBRING), RE_RSA_KEY)
        self.assertTrue(match, 'generated key check failed')
        keybits = int(match.group(1))
        self.assertLessEqual(keybits, bits, 'too much bits')
        self.assertGreater(keybits, bits - 8, 'too few bits')
        keyid = match.group(2)
        self.assertEqual(match.group(3), userid, 'wrong user id')
        # List keys using the rnpkeys
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
        self.assertEqual(ret, 0, KEY_LIST_FAILED)
        match = re.match(RE_RSA_KEY_LIST, out)
        # Compare key ids
        self.assertTrue(match, 'wrong RSA key list output')
        self.assertEqual(match.group(3)[-16:], match.group(2), 'wrong fp')
        self.assertEqual(match.group(2), keyid.lower(), 'wrong keyid')
        self.assertEqual(match.group(1), str(bits), 'wrong key bits in list')
        # Import key to the gnupg
        ret, _, _ = run_proc(GPG, ['--batch', '--passphrase', PASSWORD, '--homedir',
                                       GPGHOME, '--import',
                                       path_for_gpg(os.path.join(RNPDIR, PUBRING)),
                                       path_for_gpg(os.path.join(RNPDIR, SECRING))])
        self.assertEqual(ret, 0, 'gpg key import failed')
        # Cleanup and return
        clear_keyrings()

    def test_generate_default_rsa_key(self):
        self._rnpkey_generate_rsa()

    def test_rnpkeys_keygen_invalid_parameters(self):
        # Pass invalid numbits
        ret, _, err = run_proc(RNPK, ['--numbits', 'wrong', '--homedir', RNPDIR, '--password', 'password', 
                                      '--userid', 'wrong', '--generate-key'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(err, r'(?s)^.*wrong bits value: wrong.*')
        # Too small
        ret, _, err = run_proc(RNPK, ['--numbits', '768', '--homedir', RNPDIR, '--password', 'password', 
                                      '--userid', '768', '--generate-key'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(err, r'(?s)^.*wrong bits value: 768.*')
        # Wrong hash algorithm
        ret, _, err = run_proc(RNPK, ['--hash', 'BAD_HASH', '--homedir', RNPDIR, '--password', 'password', 
                                      '--userid', 'bad_hash', '--generate-key'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(err, r'(?s)^.*Unsupported hash algorithm: BAD_HASH.*')
        # Wrong S2K iterations
        ret, _, err = run_proc(RNPK, ['--s2k-iterations', 'WRONG_ITER', '--homedir', RNPDIR, '--password', 'password', 
                                      '--userid', 'wrong_iter', '--generate-key'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(err, r'(?s)^.*Wrong iterations value: WRONG_ITER.*')
        # Wrong S2K msec
        ret, _, err = run_proc(RNPK, ['--s2k-msec', 'WRONG_MSEC', '--homedir', RNPDIR, '--password', 'password', 
                                      '--userid', 'wrong_msec', '--generate-key'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(err, r'(?s)^.*Invalid s2k msec value: WRONG_MSEC.*')
        # Wrong cipher
        ret, _, err = run_proc(RNPK, ['--cipher', 'WRONG_AES', '--homedir', RNPDIR, '--password', 'password', 
                                      '--userid', 'wrong_aes', '--generate-key'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(err, r'(?s)^.*Unsupported symmetric algorithm: WRONG_AES.*')

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
            ret, _, _ = run_proc(RNPK, ['--numbits', '2048', '--homedir', RNPDIR, '--s2k-msec', '100',
                                        '--cipher', 'AES-128', '--pass-fd', str(pipe), '--userid', userid,
                                        '--generate-key'])
            os.close(pipe)
            self.assertEqual(ret, 0, KEY_GEN_FAILED)
            # list keys using the rnpkeys, checking whether it reports correct key
            # number
            ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
            self.assertEqual(ret, 0, KEY_LIST_FAILED)
            match = re.match(RE_MULTIPLE_KEY_LIST, out)
            self.assertTrue(match, KEY_LIST_WRONG)
            self.assertEqual(match.group(1), str((i + 1) * 2), 'wrong key count')

        # Checking the 5 keys output
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
        self.assertEqual(ret, 0, KEY_LIST_FAILED)
        self.assertRegex(out, RE_MULTIPLE_KEY_5, KEY_LIST_WRONG)

        # Cleanup and return
        clear_keyrings()

    def test_generate_key_with_gpg_import_to_rnp(self):
        '''
        Generate key with GnuPG and import it to rnp
        '''
        # Generate key in GnuPG
        ret, _, _ = run_proc(GPG, ['--batch', '--homedir', GPGHOME, '--passphrase',
                                       '', '--quick-generate-key', 'rsakey@gpg', 'rsa'])
        self.assertEqual(ret, 0, 'gpg key generation failed')
        # Getting fingerprint of the generated key
        ret, out, err = run_proc(GPG, ['--batch', '--homedir', GPGHOME, '--list-keys'])
        match = re.match(RE_GPG_SINGLE_RSA_KEY, out)
        self.assertTrue(match, 'wrong gpg key list output')
        keyfp = match.group(1)
        # Exporting generated public key
        ret, out, err = run_proc(
            GPG, ['--batch', '--homedir', GPGHOME, '--armor', '--export', keyfp])
        self.assertEqual(ret, 0, 'gpg : public key export failed')
        pubpath = os.path.join(RNPDIR, keyfp + '-pub.asc')
        with open(pubpath, 'w+') as f:
            f.write(out)
        # Exporting generated secret key
        ret, out, err = run_proc(
            GPG, ['--batch', '--homedir', GPGHOME, '--armor', '--export-secret-key', keyfp])
        self.assertEqual(ret, 0, 'gpg : secret key export failed')
        secpath = os.path.join(RNPDIR, keyfp + '-sec.asc')
        with open(secpath, 'w+') as f:
            f.write(out)
        # Importing public key to rnp
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--import-key', pubpath])
        self.assertEqual(ret, 0, 'rnp : public key import failed')
        # Importing secret key to rnp
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--import-key', secpath])
        self.assertEqual(ret, 0, 'rnp : secret key import failed')

    def test_generate_with_rnp_import_to_gpg(self):
        '''
        Generate key with RNP and export it and then import to GnuPG
        '''
        # Open pipe for password
        pipe = pswd_pipe(PASSWORD)
        # Run key generation
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--pass-fd', str(pipe),
                                        '--userid', 'rsakey@rnp', '--generate-key'])
        os.close(pipe)
        self.assertEqual(ret, 0, KEY_GEN_FAILED)
        # Export key
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--export-key', 'rsakey@rnp'])
        self.assertEqual(ret, 0, 'key export failed')
        pubpath = os.path.join(RNPDIR, 'rnpkey-pub.asc')
        with open(pubpath, 'w+') as f:
            f.write(out)
        # Import key with GPG
        ret, _, _ = run_proc(GPG, ['--batch', '--homedir', GPGHOME, '--import',
                                       path_for_gpg(pubpath)])
        self.assertEqual(ret, 0, 'gpg : public key import failed')

    def test_generate_to_kbx(self):
        '''
        Generate KBX with RNP and ensurethat the key can be read with GnuPG
        '''
        clear_keyrings()
        pipe = pswd_pipe(PASSWORD)
        kbx_userid_tracker = 'kbx_userid_tracker@rnp'
        # Run key generation
        ret, out, err = run_proc(RNPK, ['--gen-key', '--keystore-format', 'GPG21',
                                        '--userid', kbx_userid_tracker, '--homedir',
                                        RNPDIR, '--pass-fd', str(pipe)])
        os.close(pipe)
        self.assertEqual(ret, 0, KEY_GEN_FAILED)
        # Read KBX with GPG
        ret, out, err = run_proc(GPG, ['--homedir', path_for_gpg(RNPDIR), '--list-keys'])
        self.assertEqual(ret, 0, 'gpg : failed to read KBX')
        self.assertTrue(kbx_userid_tracker in out, 'gpg : failed to read expected key from KBX')
        clear_keyrings()

    def test_generate_protection_pass_fd(self):
        '''
        Generate key with RNP, using the --pass-fd parameter, and make sure key is encrypted
        '''
        clear_keyrings()
        # Open pipe for password
        pipe = pswd_pipe(PASSWORD)
        # Run key generation
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--pass-fd', str(pipe),
                                        '--userid', KEY_ENC_RNP, '--generate-key'])
        os.close(pipe)
        self.assertEqual(ret, 0, KEY_GEN_FAILED)
        # Check packets using the gpg
        params = ['--homedir', RNPDIR, '--list-packets', os.path.join(RNPDIR, SECRING)]
        ret, out, _ = run_proc(RNP, params)
        self.assertEqual(ret, 0)
        self.assertRegex(out, RE_RNP_ENCRYPTED_KEY, 'wrong encrypted secret key listing')

    def test_generate_protection_password(self):
        '''
        Generate key with RNP, using the --password parameter, and make sure key is encrypted
        '''
        clear_keyrings()
        params = ['--homedir', RNPDIR, '--password', 'password', '--userid', KEY_ENC_RNP, '--generate-key']
        ret, _, _ = run_proc(RNPK, params)
        self.assertEqual(ret, 0, KEY_GEN_FAILED)
        # Check packets using the gpg
        params = ['--homedir', RNPDIR, '--list-packets', os.path.join(RNPDIR, SECRING)]
        ret, out, _ = run_proc(RNP, params)
        self.assertEqual(ret, 0)
        self.assertRegex(out, RE_RNP_ENCRYPTED_KEY, 'wrong encrypted secret key listing')
    
    def test_generate_unprotected_key(self):
        '''
        Generate key with RNP, using the --password parameter, and make sure key is encrypted
        '''
        clear_keyrings()
        params = ['--homedir', RNPDIR, '--password=', '--userid', KEY_ENC_RNP, '--generate-key']
        ret, _, _ = run_proc(RNPK, params)
        self.assertEqual(ret, 0, KEY_GEN_FAILED)
        # Check packets using the gpg
        params = ['--homedir', RNPDIR, '--list-packets', os.path.join(RNPDIR, SECRING)]
        ret, out, _ = run_proc(RNP, params)
        self.assertEqual(ret, 0)
        self.assertNotRegex(out, RE_RNP_ENCRYPTED_KEY, 'wrong unprotected secret key listing')

    def test_generate_preferences(self):
        pipe = pswd_pipe(PASSWORD)
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--pass-fd', str(pipe), '--userid',
                                      'eddsa_25519_prefs', '--generate-key', '--expert'], '22\n')
        os.close(pipe)
        self.assertEqual(ret, 0)
        ret, out, _ = run_proc(RNP, ['--list-packets', os.path.join(RNPDIR, PUBRING)])
        self.assertRegex(out, r'.*preferred symmetric algorithms: AES-256, AES-192, AES-128 \(9, 8, 7\).*')
        self.assertRegex(out, r'.*preferred hash algorithms: SHA256, SHA384, SHA512, SHA224 \(8, 9, 10, 11\).*')

    def test_import_signatures(self):
        clear_keyrings()
        RE_SIG_2_UNCHANGED = r'(?s)^.*Import finished: 0 new signatures, 2 unchanged, 0 unknown.*'
        # Import command without the path parameter
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--import-sigs'])
        self.assertNotEqual(ret, 0, 'Sigs import without file failed')
        self.assertRegex(err, r'(?s)^.*Import path isn\'t specified.*', 'Sigs import without file wrong output')
        # Import command with invalid path parameter
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--import-sigs', data_path('test_key_validity/alice-rev-no-file.pgp')])
        self.assertNotEqual(ret, 0, 'Sigs import with invalid path failed')
        self.assertRegex(err, r'(?s)^.*Failed to create input for .*', 'Sigs import with invalid path wrong output')
        # Try to import signature to empty keyring
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--import-sigs', data_path('test_key_validity/alice-rev.pgp')])
        self.assertEqual(ret, 0, 'Alice key rev import failed')
        self.assertRegex(err, r'(?s)^.*Import finished: 0 new signatures, 0 unchanged, 1 unknown.*', 'Alice key rev import wrong output')
        # Import Basil's key
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--import', data_path('test_key_validity/basil-pub.asc')])
        self.assertEqual(ret, 0, 'Basil key import failed')
        # Try to import Alice's signatures with Basil's key only 
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--import', data_path('test_key_validity/alice-sigs.pgp')])
        self.assertEqual(ret, 0, 'Alice sigs import failed')
        self.assertRegex(err, r'(?s)^.*Import finished: 0 new signatures, 0 unchanged, 2 unknown.*', 'Alice sigs import wrong output')
        # Import Alice's key without revocation/direct-key signatures
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--import', data_path(KEY_ALICE_PUB)])
        self.assertEqual(ret, 0, ALICE_IMPORT_FAIL)
        # Import key revocation signature
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--import-sigs', data_path('test_key_validity/alice-rev.pgp')])
        self.assertEqual(ret, 0, 'Alice key rev import failed')
        self.assertRegex(err, RE_SIG_1_IMPORT, 'Alice key rev import wrong output')
        # Import direct-key signature
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--import', data_path('test_key_validity/alice-revoker-sig.pgp')])
        self.assertEqual(ret, 0, 'Alice direct-key sig import failed')
        self.assertRegex(err, RE_SIG_1_IMPORT, 'Alice direct-key sig import wrong output')
        # Try to import two signatures again
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--import', data_path('test_key_validity/alice-sigs.pgp')])
        self.assertEqual(ret, 0, 'Alice sigs reimport failed')
        self.assertRegex(err, RE_SIG_2_UNCHANGED, 'Alice sigs file reimport wrong output')
        # Import two signatures again via stdin
        stext = file_text(data_path('test_key_validity/alice-sigs.asc'))
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--import', '-'], stext)
        self.assertEqual(ret, 0, 'Alice sigs stdin reimport failed')
        self.assertRegex(err, RE_SIG_2_UNCHANGED, 'Alice sigs stdin reimport wrong output')
        # Import two signatures via env variable
        os.environ["SIG_FILE"] = stext
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--import', 'env:SIG_FILE'])
        self.assertEqual(ret, 0, 'Alice sigs env reimport failed')
        self.assertRegex(err, RE_SIG_2_UNCHANGED, 'Alice sigs var reimport wrong output')
        # Try to import malformed signatures
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--import', data_path('test_key_validity/alice-sigs-malf.pgp')])
        self.assertNotEqual(ret, 0, 'Alice malformed sigs import failed')
        self.assertRegex(err, r'(?s)^.*Failed to import signatures from .*', 'Alice malformed sigs wrong output')
    
    def test_export_revocation(self):
        clear_keyrings()
        OUT_NO_REV = 'no-revocation.pgp'
        OUT_ALICE_REV = 'alice-revocation.pgp'
        # Import Alice's public key and be unable to export revocation
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--import', data_path(KEY_ALICE_PUB)])
        self.assertEqual(ret, 0, ALICE_IMPORT_FAIL)
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--export-rev', 'alice'])
        self.assertNotEqual(ret, 0)
        self.assertEqual(len(out), 0)
        self.assertRegex(err, r'(?s)^.*Revoker secret key not found.*', 'Wrong pubkey revocation export output')
        # Import Alice's secret key and subkey
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--import', data_path(KEY_ALICE_SUB_SEC)])
        self.assertEqual(ret, 0, 'Alice secret key import failed')
        # Attempt to export revocation without specifying key
        pipe = pswd_pipe(PASSWORD)
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--export-rev', '--pass-fd', str(pipe)])
        os.close(pipe)
        self.assertNotEqual(ret, 0)
        self.assertEqual(len(out), 0)
        self.assertRegex(err, r'(?s)^.*You need to specify key to generate revocation for.*', 'Wrong no key revocation export output')
        # Attempt to export revocation for unknown key
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--export-rev', 'basil'])
        self.assertNotEqual(ret, 0)
        self.assertEqual(len(out), 0)
        self.assertRegex(err, r'(?s)^.*Key matching \'basil\' not found.*', 'Wrong unknown key revocation export output')
        # Attempt to export revocation for subkey
        pipe = pswd_pipe(PASSWORD)
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--export-rev', 'DD23CEB7FEBEFF17'])
        os.close(pipe)
        self.assertNotEqual(ret, 0)
        self.assertEqual(len(out), 0)
        self.assertRegex(err, r'(?s)^.*Key matching \'DD23CEB7FEBEFF17\' not found.*', 'Wrong subkey revocation export output')
        # Attempt to export revocation with too broad search
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--import', data_path('test_key_validity/basil-sec.asc')])
        self.assertEqual(ret, 0, 'Basil secret key import failed')
        pipe = pswd_pipe(PASSWORD)
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--export-rev', 'rnp', '--pass-fd', str(pipe), 
                                      '--output', OUT_NO_REV, '--force'])
        os.close(pipe)
        self.assertNotEqual(ret, 0, 'Failed to fail to export revocation')
        self.assertFalse(os.path.isfile(OUT_NO_REV), 'Failed to fail to export revocation')
        self.assertRegex(err, r'(?s)^.*Ambiguous input: too many keys found for \'rnp\'.*', 'Wrong revocation export output')
        # Finally successfully export revocation
        pipe = pswd_pipe(PASSWORD)
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--export-rev', '0451409669FFDE3C', '--pass-fd', str(pipe), 
                                    '--output', OUT_ALICE_REV, '--overwrite'])
        os.close(pipe)
        self.assertEqual(ret, 0)
        self.assertTrue(os.path.isfile(OUT_ALICE_REV))
        # Check revocation contents
        ret, out, _ = run_proc(RNP, ['--homedir', RNPDIR, '--list-packets', OUT_ALICE_REV])
        self.assertEqual(ret, 0)
        self.assertNotEqual(len(out), 0)
        match = re.match(RE_RNP_REVOCATION_SIG, out)
        self.assertTrue(match, 'Wrong revocation signature contents')
        self.assertEqual(match.group(1).strip(), '0 (No reason)', 'Wrong revocation signature reason')
        self.assertEqual(match.group(2).strip(), '', 'Wrong revocation signature message')
        # Make sure it can be imported back
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--import-sigs', OUT_ALICE_REV])
        self.assertEqual(ret, 0, 'Failed to import revocation back')
        self.assertRegex(err, RE_SIG_1_IMPORT, 'Revocation import wrong output')
        # Make sure file will not be overwritten with --force parameter
        with open(OUT_ALICE_REV, 'w+') as f:
            f.truncate(10)
        pipe = pswd_pipe(PASSWORD)
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--export-rev', '0451409669FFDE3C', '--pass-fd', str(pipe), '--output', OUT_ALICE_REV, '--force', '--notty'], '\n\n')
        os.close(pipe)
        self.assertNotEqual(ret, 0, 'Revocation was overwritten with --force')
        self.assertEqual(10, os.stat(OUT_ALICE_REV).st_size, 'Revocation was overwritten with --force')
        # Make sure file will not be overwritten without --overwrite parameter
        pipe = pswd_pipe(PASSWORD)
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--export-rev', '0451409669FFDE3C', '--pass-fd', str(pipe), '--output', OUT_ALICE_REV, '--notty'], '\n\n')
        os.close(pipe)
        self.assertNotEqual(ret, 0, 'Revocation was overwritten without --overwrite and --force')
        self.assertTrue(os.path.isfile(OUT_ALICE_REV), 'Revocation was overwritten without --overwrite')
        self.assertEqual(10, os.stat(OUT_ALICE_REV).st_size, 'Revocation was overwritten without --overwrite')
        # Make sure file will be overwritten with --overwrite parameter
        pipe = pswd_pipe(PASSWORD)
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--export-rev', '0451409669FFDE3C', '--pass-fd', str(pipe), '--output', OUT_ALICE_REV, '--overwrite'])
        os.close(pipe)
        self.assertEqual(ret, 0)
        self.assertGreater(os.stat(OUT_ALICE_REV).st_size, 10)
        # Create revocation with wrong code - 'no longer valid' (which is usable only for userid)
        pipe = pswd_pipe(PASSWORD)
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--export-rev', 'alice', '--rev-type', 'no longer valid',
                                        '--pass-fd', str(pipe), '--output', OUT_NO_REV, '--force'])
        os.close(pipe)
        self.assertNotEqual(ret, 0, 'Failed to use wrong revocation reason')
        self.assertFalse(os.path.isfile(OUT_NO_REV))
        self.assertRegex(err, r'(?s)^.*Wrong key revocation code: 32.*', 'Wrong revocation export output')
        # Create revocation without rev-code parameter
        pipe = pswd_pipe(PASSWORD)
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--export-rev', 'alice', '--pass-fd', str(pipe), 
                                        '--output', OUT_NO_REV, '--force', '--rev-type'])
        os.close(pipe)
        self.assertNotEqual(ret, 0, 'Failed to use rev-type without parameter')
        self.assertFalse(os.path.isfile(OUT_NO_REV), 'Failed to use rev-type without parameter')
        # Create another revocation with custom code/reason
        revcodes = {"0" : "0 (No reason)", "1" : "1 (Superseded)", "2" : "2 (Compromised)", 
                    "3" : "3 (Retired)", "no" : "0 (No reason)", "superseded" : "1 (Superseded)", 
                    "compromised" : "2 (Compromised)", "retired" : "3 (Retired)"}
        for revcode in revcodes:
            revreason = 'Custom reason: ' + revcode
            pipe = pswd_pipe(PASSWORD)
            ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--export-rev', '0451409669FFDE3C', '--pass-fd', str(pipe), 
                                            '--output', OUT_ALICE_REV, '--overwrite', '--rev-type', revcode, '--rev-reason', revreason])
            os.close(pipe)
            self.assertEqual(ret, 0, 'Failed to export revocation with code ' + revcode)
            self.assertTrue(os.path.isfile(OUT_ALICE_REV), 'Failed to export revocation with code ' + revcode)
            # Check revocation contents
            ret, out, _ = run_proc(RNP, ['--homedir', RNPDIR, '--list-packets', OUT_ALICE_REV])
            self.assertEqual(ret, 0, 'Failed to list exported revocation packets')
            self.assertNotEqual(len(out), 0, 'Failed to list exported revocation packets')
            match = re.match(RE_RNP_REVOCATION_SIG, out)
            self.assertTrue(match)
            self.assertEqual(match.group(1).strip(), revcodes[revcode], 'Wrong revocation signature revcode')
            self.assertEqual(match.group(2).strip(), revreason, 'Wrong revocation signature reason')
            # Make sure it is also imported back
            ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--import-sigs', OUT_ALICE_REV])
            self.assertEqual(ret, 0)
            self.assertRegex(err, RE_SIG_1_IMPORT, 'Revocation import wrong output')
            # Now let's import it with GnuPG
            gpg_import_pubring(data_path(KEY_ALICE_PUB))
            ret, _, err = run_proc(GPG, ['--batch', '--homedir', GPGHOME, '--import', OUT_ALICE_REV])
            self.assertEqual(ret, 0, 'gpg signature revocation import failed')
            self.assertRegex(err, RE_GPG_REVOCATION_IMPORT, 'Wrong gpg revocation import output')

        os.remove(OUT_ALICE_REV)
        clear_keyrings()

    def test_export_keys(self):
        PUB_KEY = r'(?s)^.*' \
        r'-----BEGIN PGP PUBLIC KEY BLOCK-----.*' \
        r'-----END PGP PUBLIC KEY BLOCK-----.*$'        
        PUB_KEY_PKTS = r'(?s)^.*' \
        r'Public key packet.*' \
        r'keyid: 0x0451409669ffde3c.*' \
        r'Public subkey packet.*' \
        r'keyid: 0xdd23ceb7febeff17.*$'
        SEC_KEY = r'(?s)^.*' \
        r'-----BEGIN PGP PRIVATE KEY BLOCK-----.*' \
        r'-----END PGP PRIVATE KEY BLOCK-----.*$'
        SEC_KEY_PKTS = r'(?s)^.*' \
        r'Secret key packet.*' \
        r'keyid: 0x0451409669ffde3c.*' \
        r'Secret subkey packet.*' \
        r'keyid: 0xdd23ceb7febeff17.*$'
        KEY_OVERWRITE = r'(?s)^.*' \
        r'File \'.*alice-key.pub.asc\' already exists.*' \
        r'Would you like to overwrite it\? \(y/N\).*' \
        r'Please enter the new filename:.*$'

        clear_keyrings()
        # Import Alice's public key
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--import', data_path('test_key_validity/alice-sub-pub.pgp')])
        self.assertEqual(ret, 0)
        # Attempt to export no key
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--export-key'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(err, r'(?s)^.*No key specified\.$')
        # Attempt to export wrong key
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--export-key', 'boris'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(err, r'(?s)^.*Key\(s\) matching \'boris\' not found\.$')
        # Export it to the stdout
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--export-key', 'alice'])
        self.assertEqual(ret, 0)
        self.assertRegex(out, PUB_KEY)
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--export-key', 'alice', '--output', '-'])
        self.assertEqual(ret, 0)
        self.assertRegex(out, PUB_KEY)
        # Export key via --userid parameter
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--export-key', '--userid', 'alice'])
        self.assertEqual(ret, 0)
        self.assertRegex(out, PUB_KEY)
        # Export with empty --userid parameter
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--export-key', '--userid'])
        self.assertNotEqual(ret, 0)
        # Export it to the file
        kpub, ksec, kren = reg_workfiles('alice-key', '.pub.asc', '.sec.asc', '.pub.ren-asc')
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--export-key', 'alice', '--output', kpub])
        self.assertEqual(ret, 0)
        self.assertRegex(file_text(kpub), PUB_KEY)
        # Try to export again to the same file without additional parameters
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--export-key', 'alice', '--output', kpub, '--notty'], '\n\n')
        self.assertNotEqual(ret, 0)
        self.assertRegex(out, KEY_OVERWRITE)
        self.assertRegex(err, r'(?s)^.*Operation failed: file \'.*alice-key.pub.asc\' already exists.*$')
        # Try to export with --force parameter
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--export-key', 'alice', '--output', kpub, '--force', '--notty'], '\n\n')
        self.assertNotEqual(ret, 0)
        self.assertRegex(out, KEY_OVERWRITE)
        self.assertRegex(err, r'(?s)^.*Operation failed: file \'.*alice-key.pub.asc\' already exists.*$')
        # Export with --overwrite parameter
        with open(kpub, 'w+') as f:
            f.truncate(10)
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--export-key', 'alice', '--output', kpub, '--overwrite'])
        self.assertEqual(ret, 0)
        # Re-import it, making sure file was correctly overwriten
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--import', kpub])
        self.assertEqual(ret, 0)
        # Enter 'y' in ovewrite prompt
        with open(kpub, 'w+') as f:
            f.truncate(10)
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--export-key', 'alice', '--output', kpub, '--notty'], 'y\n')
        self.assertEqual(ret, 0)
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--import', kpub])
        self.assertEqual(ret, 0)
        # Enter new filename in overwrite prompt
        with open(kpub, 'w+') as f:
            f.truncate(10)
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--export-key', 'alice', '--output', kpub, '--notty'], 'n\n' + kren + '\n')
        self.assertEqual(ret, 0)
        self.assertEqual(os.path.getsize(kpub), 10)
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--import', kren])
        self.assertEqual(ret, 0)
        # Attempt to export secret key
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--export-key', '--secret', 'alice'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(err, r'(?s)^.*Key\(s\) matching \'alice\' not found\.$')
        # Import Alice's secret key and subkey
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--import', data_path(KEY_ALICE_SUB_SEC)])
        self.assertEqual(ret, 0)
        # Make sure secret key is not exported when public is requested
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--export-key', 'alice', '--output', ksec])
        self.assertEqual(ret, 0)
        self.assertRegex(file_text(ksec), PUB_KEY)
        ret, out, _ = run_proc(RNP, ['--list-packets', ksec])
        self.assertEqual(ret, 0)
        self.assertRegex(out, PUB_KEY_PKTS)
        # Make sure secret key is correctly exported
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--export-key', '--secret', 'alice', '--output', ksec, '--overwrite'])
        self.assertEqual(ret, 0)
        self.assertRegex(file_text(ksec), SEC_KEY)
        ret, out, _ = run_proc(RNP, ['--list-packets', ksec])
        self.assertEqual(ret, 0)
        self.assertRegex(out, SEC_KEY_PKTS)
        clear_keyrings()

    def test_userid_escape(self):
        clear_keyrings()
        tracker_beginning = 'tracker'
        tracker_end = '@rnp'
        tracker_1 = tracker_beginning + ''.join(map(lambda x : chr(x), range(1,0x10))) + tracker_end
        tracker_2 = tracker_beginning + ''.join(map(lambda x : chr(x), range(0x10,0x20))) + tracker_end
        #Run key generation
        rnp_genkey_rsa(tracker_1, 1024)
        rnp_genkey_rsa(tracker_2, 1024)
        #Read with rnpkeys
        ret, out_rnp, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
        self.assertEqual(ret, 0, 'rnpkeys : failed to read keystore')
        #Read with GPG
        ret, out_gpg, _ = run_proc(GPG, ['--homedir', path_for_gpg(RNPDIR), '--list-keys'])
        self.assertEqual(ret, 0, 'gpg : failed to read keystore')
        tracker_rnp = re.findall(r'' + tracker_beginning + '.*' + tracker_end + '', out_rnp)
        tracker_gpg = re.findall(r'' + tracker_beginning + '.*' + tracker_end + '', out_gpg)
        self.assertEqual(len(tracker_rnp), 2, 'failed to find expected rnp userids')
        self.assertEqual(len(tracker_gpg), 2, 'failed to find expected gpg userids')
        self.assertEqual(tracker_rnp, tracker_gpg, 'userids from rnpkeys and gpg don\'t match')
        clear_keyrings()

    def test_key_revoke(self):
        clear_keyrings()
        # Import Alice's public key and be unable to revoke
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--import', data_path(KEY_ALICE_PUB)])
        self.assertEqual(ret, 0, ALICE_IMPORT_FAIL)
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--revoke-key', 'alice'])
        self.assertNotEqual(ret, 0)
        self.assertEqual(len(out), 0)
        self.assertRegex(err, r'(?s)^.*Revoker secret key not found.*Failed to revoke a key.*')
        # Import Alice's secret key and subkey
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--import', data_path(KEY_ALICE_SUB_SEC)])
        self.assertEqual(ret, 0)
        # Attempt to revoke without specifying a key
        pipe = pswd_pipe(PASSWORD)
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--revoke', '--pass-fd', str(pipe)])
        os.close(pipe)
        self.assertNotEqual(ret, 0)
        self.assertEqual(len(out), 0)
        self.assertRegex(err, r'(?s)^.*You need to specify key or subkey to revoke.*')
        # Attempt to revoke unknown key
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--revoke', 'basil'])
        self.assertNotEqual(ret, 0)
        self.assertEqual(len(out), 0)
        self.assertRegex(err, r'(?s)^.*Key matching \'basil\' not found.*')
        # Attempt to revoke with too broad search
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--import', data_path('test_key_validity/basil-sec.asc')])
        self.assertEqual(ret, 0)
        pipe = pswd_pipe(PASSWORD)
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--revoke', 'rnp', '--pass-fd', str(pipe)])
        os.close(pipe)
        self.assertRegex(err, r'(?s)^.*Ambiguous input: too many keys found for \'rnp\'.*')
        # Revoke a primary key
        pipe = pswd_pipe(PASSWORD)
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--revoke', '0451409669FFDE3C', '--pass-fd', str(pipe)])
        os.close(pipe)
        self.assertEqual(ret, 0)
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
        self.assertEqual(ret, 0)
        self.assertRegex(out, r'(?s)^.*pub.*0451409669ffde3c.*\[REVOKED\].*73edcc9119afc8e2dbbdcde50451409669ffde3c.*')
        # Try again without the '--force' parameter
        pipe = pswd_pipe(PASSWORD)
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--revoke', '0451409669FFDE3C', '--pass-fd', str(pipe)])
        os.close(pipe)
        self.assertNotEqual(ret, 0)
        self.assertEqual(len(out), 0)
        self.assertRegex(err, r'(?s)^.*Error: key \'0451409669FFDE3C\' is revoked already. Use --force to generate another revocation signature.*')
        # Try again with --force parameter
        pipe = pswd_pipe(PASSWORD)
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--revoke', '0451409669FFDE3C', '--pass-fd', str(pipe), "--force", "--rev-type", "3", "--rev-reason", "Custom"])
        os.close(pipe)
        self.assertEqual(ret, 0)
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
        self.assertEqual(ret, 0)
        self.assertRegex(out, r'(?s)^.*pub.*0451409669ffde3c.*\[REVOKED\].*73edcc9119afc8e2dbbdcde50451409669ffde3c.*')
        # Revoke a subkey
        pipe = pswd_pipe(PASSWORD)
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--revoke', 'DD23CEB7FEBEFF17', '--pass-fd', str(pipe)])
        os.close(pipe)
        self.assertEqual(ret, 0)
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
        self.assertEqual(ret, 0)
        self.assertRegex(out, r'(?s)^.*sub.*dd23ceb7febeff17.*\[REVOKED\].*a4bbb77370217bca2307ad0ddd23ceb7febeff17.*')
        # Try again without the '--force' parameter
        pipe = pswd_pipe(PASSWORD)
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--revoke', 'DD23CEB7FEBEFF17', '--pass-fd', str(pipe)])
        os.close(pipe)
        self.assertNotEqual(ret, 0)
        self.assertEqual(len(out), 0)
        self.assertRegex(err, r'(?s)^.*Error: key \'DD23CEB7FEBEFF17\' is revoked already. Use --force to generate another revocation signature.*', err)
        # Try again with --force parameter
        pipe = pswd_pipe(PASSWORD)
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--revoke', 'DD23CEB7FEBEFF17', '--pass-fd', str(pipe), "--force", "--rev-type", "2", "--rev-reason", "Other"])
        os.close(pipe)
        self.assertEqual(ret, 0)
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
        self.assertEqual(ret, 0)
        self.assertRegex(out, r'(?s)^.*sub.*dd23ceb7febeff17.*\[REVOKED\].*a4bbb77370217bca2307ad0ddd23ceb7febeff17.*')

    def _test_userid_genkey(self, userid_beginning, weird_part, userid_end, weird_part2=''):
        clear_keyrings()
        USERS = [userid_beginning + weird_part + userid_end]
        if weird_part2:
            USERS.append(userid_beginning + weird_part2 + userid_end)
        # Run key generation
        for userid in USERS:
            rnp_genkey_rsa(userid, 1024)
        # Read with GPG
        ret, out, err = run_proc(GPG, ['--homedir', path_for_gpg(RNPDIR), '--list-keys', '--charset', CONSOLE_ENCODING])
        self.assertEqual(ret, 0, 'gpg : failed to read keystore')
        tracker_escaped = re.findall(r'' + userid_beginning + '.*' + userid_end + '', out)
        tracker_gpg = list(map(decode_string_escape, tracker_escaped))
        self.assertEqual(tracker_gpg, USERS, 'gpg : failed to find expected userids from keystore')
        # Read with rnpkeys
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
        self.assertEqual(ret, 0, 'rnpkeys : failed to read keystore')
        tracker_escaped = re.findall(r'' + userid_beginning + '.*' + userid_end + '', out)
        tracker_rnp = list(map(decode_string_escape, tracker_escaped))
        self.assertEqual(tracker_rnp, USERS, 'rnpkeys : failed to find expected userids from keystore')
        clear_keyrings()

    def test_userid_unicode_genkeys(self):
        self._test_userid_genkey('track', WEIRD_USERID_UNICODE_1, 'end', WEIRD_USERID_UNICODE_2)

    def test_userid_special_chars_genkeys(self):
        self._test_userid_genkey('track', WEIRD_USERID_SPECIAL_CHARS, 'end')
        self._test_userid_genkey('track', WEIRD_USERID_SPACE, 'end')
        self._test_userid_genkey('track', WEIRD_USERID_QUOTE, 'end')
        self._test_userid_genkey('track', WEIRD_USERID_SPACE_AND_QUOTE, 'end')

    def test_userid_too_long_genkeys(self):
        clear_keyrings()
        userid = WEIRD_USERID_TOO_LONG
        # Open pipe for password
        pipe = pswd_pipe(PASSWORD)
        # Run key generation
        ret, _, _ = run_proc(RNPK, ['--gen-key', '--userid', userid,
                                    '--homedir', RNPDIR, '--pass-fd', str(pipe)])
        os.close(pipe)
        self.assertNotEqual(ret, 0, 'should have failed on too long id')

    def test_key_remove(self):
        MSG_KEYS_NOT_FOUND = r'Key\(s\) not found\.'
        clear_keyrings()
        # Import public keyring
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--import', data_path(PUBRING_1)])
        self.assertEqual(ret, 0)
        # Remove without parameters
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--remove-key'])
        self.assertNotEqual(ret, 0)
        # Remove all imported public keys with subkeys
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--remove-key', '7bc6709b15c23a4a', '2fcadf05ffa501bb'])
        self.assertEqual(ret, 0)
        # Check that keyring is empty
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(out, MSG_KEYS_NOT_FOUND, 'Invalid no-keys output')
        # Import secret keyring
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--import', data_path('keyrings/1/secring.gpg')])
        self.assertEqual(ret, 0, 'Secret keyring import failed')
        # Remove all secret keys with subkeys
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--remove-key', '7bc6709b15c23a4a', '2fcadf05ffa501bb', '--force'])
        self.assertEqual(ret, 0, 'Failed to remove 2 secret keys')
        # Check that keyring is empty
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(out, MSG_KEYS_NOT_FOUND, 'Failed to remove secret keys')
        # Import public keyring
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--import', data_path(PUBRING_1)])
        self.assertEqual(ret, 0, 'Public keyring import failed')
        # Remove all subkeys
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--remove-key',
                                        '326ef111425d14a5', '54505a936a4a970e', '8a05b89fad5aded1', '1d7e8a5393c997a8', '1ed63ee56fadc34d'])
        self.assertEqual(ret, 0, 'Failed to remove 5 keys')
        # Check that subkeys are removed
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
        self.assertEqual(ret, 0)
        self.assertRegex(out, r'2 keys found', 'Failed to remove subkeys')
        self.assertFalse(re.search('326ef111425d14a5|54505a936a4a970e|8a05b89fad5aded1|1d7e8a5393c997a8|1ed63ee56fadc34d', out))
        # Remove remaining public keys
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--remove-key', '7bc6709b15c23a4a', '2fcadf05ffa501bb'])
        self.assertEqual(ret, 0, 'Failed to remove public keys')
        # Try to remove again
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--remove-key', '7bc6709b15c23a4a'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(err, r'Key matching \'7bc6709b15c23a4a\' not found\.', 'Unexpected result')
        # Check that keyring is empty
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
        self.assertRegex(out, MSG_KEYS_NOT_FOUND, 'Failed to list empty keyring')
        # Import public keyring
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--import', data_path(PUBRING_1)])
        self.assertEqual(ret, 0, 'Public keyring import failed')
        # Try to remove by uid substring, should match multiple keys and refuse to remove
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--remove-key', 'uid0'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(err, r'Ambiguous input: too many keys found for \'uid0\'\.', 'Unexpected result')
        # Remove keys by uids
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--remove-key', 'key0-uid0', 'key1-uid1'])
        self.assertEqual(ret, 0, 'Failed to remove keys')
        # Check that keyring is empty
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(out, MSG_KEYS_NOT_FOUND, 'Failed to remove keys')

class Misc(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        rnp_genkey_rsa(KEY_ENCRYPT)
        rnp_genkey_rsa(KEY_SIGN_GPG)
        gpg_import_pubring()
        gpg_import_secring()

    @classmethod
    def tearDownClass(cls):
        clear_keyrings()

    def tearDown(self):
        clear_workfiles()

    def test_encryption_unicode(self):
        if sys.version_info >= (3,):
            filename = UNICODE_SEQUENCE_1
        else:
            filename = UNICODE_SEQUENCE_1.encode(CONSOLE_ENCODING)

        src, dst, dec = reg_workfiles(filename, '.txt', '.rnp', '.dec')
        # Generate random file of required size
        random_text(src, 128000)

        rnp_encrypt_file_ex(src, dst, [KEY_ENCRYPT])
        rnp_decrypt_file(dst, dec)
        compare_files(src, dec, RNP_DATA_DIFFERS)

        remove_files(src, dst, dec)

    def test_encryption_no_mdc(self):
        src, dst, dec = reg_workfiles('cleartext', '.txt', '.gpg', '.rnp')
        # Generate random file of required size
        random_text(src, 64000)
        # Encrypt cleartext file with GPG
        params = ['--homedir', GPGHOME, '-c', '-z', '0', '--disable-mdc', '--s2k-count',
                  '65536', '--batch', '--passphrase', PASSWORD, '--output',
                  path_for_gpg(dst), path_for_gpg(src)]
        ret, _, _ = run_proc(GPG, params)
        self.assertEqual(ret, 0, 'gpg symmetric encryption failed')
        # Decrypt encrypted file with RNP
        rnp_decrypt_file(dst, dec)
        compare_files(src, dec, RNP_DATA_DIFFERS)

    def test_encryption_s2k(self):
        src, dst, dec = reg_workfiles('cleartext', '.txt', '.gpg', '.rnp')
        random_text(src, 1000)

        ciphers = ['AES', 'AES192', 'AES256', 'TWOFISH', 'CAMELLIA128', 'CAMELLIA192',
                   'CAMELLIA256', 'IDEA', '3DES', 'CAST5', 'BLOWFISH']
        hashes = ['SHA1', 'RIPEMD160', 'SHA256', 'SHA384', 'SHA512', 'SHA224']
        s2kmodes = [0, 1, 3]

        if not RNP_TWOFISH:
            ciphers.remove('TWOFISH')

        def rnp_encryption_s2k_gpg(cipher, hash_alg, s2k=None, iterations=None):
            params = ['--homedir', GPGHOME, '-c', '--s2k-cipher-algo', cipher, 
                      '--s2k-digest-algo', hash_alg, '--batch', '--passphrase', PASSWORD,
                      '--output', dst, src]

            if s2k is not None:
                params.insert(7, '--s2k-mode')
                params.insert(8, str(s2k))

                if iterations is not None:
                    params.insert(9, '--s2k-count')
                    params.insert(10, str(iterations))

            if GPG_NO_OLD:
                params.insert(3, '--allow-old-cipher-algos')

            ret, _, _ = run_proc(GPG, params)
            self.assertEqual(ret, 0, 'gpg symmetric encryption failed')
            rnp_decrypt_file(dst, dec)
            compare_files(src, dec, RNP_DATA_DIFFERS)
            remove_files(dst, dec)

        for i in range(0, 20):
            rnp_encryption_s2k_gpg(ciphers[i % len(ciphers)], hashes[
                                i % len(hashes)], s2kmodes[i % len(s2kmodes)])

    def test_armor(self):
        src_beg, dst_beg, dst_mid, dst_fin = reg_workfiles('beg', '.src', '.dst',
                                                           '.mid.dst', '.fin.dst')
        armor_types = [('msg', 'MESSAGE'), ('pubkey', 'PUBLIC KEY BLOCK'),
                       ('seckey', 'PRIVATE KEY BLOCK'), ('sign', 'SIGNATURE')]

        # Wrong armor type
        ret, _, err = run_proc(RNP, ['--enarmor', 'wrong', src_beg, '--output', dst_beg])
        self.assertNotEqual(ret, 0)
        self.assertRegex(err, r'(?s)^.*Wrong enarmor argument: wrong.*$')

        for data_type, header in armor_types:
            random_text(src_beg, 1000)
            prefix = '-----BEGIN PGP ' + header + '-----'
            suffix = '-----END PGP ' + header + '-----'

            ret, _, _ = run_proc(RNP, ['--enarmor', data_type, src_beg, '--output', dst_beg])
            self.assertEqual(ret, 0)
            txt = file_text(dst_beg).strip('\r\n')

            self.assertTrue(txt.startswith(prefix), 'wrong armor header')
            self.assertTrue(txt.endswith(suffix), 'wrong armor trailer')

            ret, _, _ = run_proc(RNP, ['--dearmor', dst_beg, '--output', dst_mid])
            self.assertEqual(ret, 0)
            ret, _, _ = run_proc(RNP, ['--enarmor', data_type, dst_mid, '--output', dst_fin])
            self.assertEqual(ret, 0)

            compare_files(dst_beg, dst_fin, "RNP armor/dearmor test failed")
            compare_files(src_beg, dst_mid, "RNP armor/dearmor test failed")
            remove_files(dst_beg, dst_mid, dst_fin)

    def test_rnpkeys_lists(self):
        KEYRING_1 = data_path('keyrings/1')
        KEYRING_2 = data_path('keyrings/2')
        KEYRING_3 = data_path('keyrings/3')
        KEYRING_5 = data_path('keyrings/5')
        path = data_path('test_cli_rnpkeys') + '/'

        _, out, _ = run_proc(RNPK, ['--homedir', KEYRING_1, '--list-keys'])
        compare_file_any(allow_y2k38_on_32bit(path + 'keyring_1_list_keys'), out, 'keyring 1 key listing failed')
        _, out, _ = run_proc(RNPK, ['--hom', KEYRING_1, '-l', '--with-sigs'])
        compare_file_any(allow_y2k38_on_32bit(path + 'keyring_1_list_sigs'), out, 'keyring 1 sig listing failed')
        _, out, _ = run_proc(RNPK, ['--home', KEYRING_1, '--list-keys', '--secret'])
        compare_file_any(allow_y2k38_on_32bit(path + 'keyring_1_list_keys_sec'), out, 'keyring 1 sec key listing failed')
        _, out, _ = run_proc(RNPK, ['--home', KEYRING_1, '--list-keys',
                                    '--secret', '--with-sigs'])
        compare_file_any(allow_y2k38_on_32bit(path + 'keyring_1_list_sigs_sec'), out, 'keyring 1 sec sig listing failed')

        _, out, _ = run_proc(RNPK, ['--homedir', KEYRING_2, '--list-keys'])
        compare_file(path + 'keyring_2_list_keys', out, 'keyring 2 key listing failed')
        _, out, _ = run_proc(RNPK, ['--homedir', KEYRING_2, '-l', '--with-sigs'])
        compare_file(path + 'keyring_2_list_sigs', out, 'keyring 2 sig listing failed')

        _, out, _ = run_proc(RNPK, ['--homedir', KEYRING_3, '--list-keys'])
        compare_file_any(allow_y2k38_on_32bit(path + 'keyring_3_list_keys'), out, 'keyring 3 key listing failed')
        _, out, _ = run_proc(RNPK, ['--homedir', KEYRING_3, '-l', '--with-sigs'])
        compare_file_any(allow_y2k38_on_32bit(path + 'keyring_3_list_sigs'), out, 'keyring 3 sig listing failed')

        _, out, _ = run_proc(RNPK, ['--homedir', KEYRING_5, '--list-keys'])
        compare_file(path + 'keyring_5_list_keys', out, 'keyring 5 key listing failed')
        _, out, _ = run_proc(RNPK, ['--homedir', KEYRING_5, '-l', '--with-sigs'])
        compare_file(path + 'keyring_5_list_sigs', out, 'keyring 5 sig listing failed')

        _, out, _ = run_proc(RNPK, ['--homedir', data_path(SECRING_G10),
                                    '--list-keys'])
        if RNP_BRAINPOOL:
            self.assertEqual(file_text(path + 'test_stream_key_load_keys'), out, 'g10 keyring key listing failed')
        else:
            self.assertEqual(file_text(path + 'test_stream_key_load_keys_no_bp'), out, 'g10 keyring key listing failed')
        _, out, _ = run_proc(RNPK, ['--homedir', data_path(SECRING_G10),
                                    '-l', '--with-sigs'])
        if RNP_BRAINPOOL:
            self.assertEqual(file_text(path + 'test_stream_key_load_sigs'), out, 'g10 keyring sig listing failed')
        else:
            self.assertEqual(file_text(path + 'test_stream_key_load_sigs_no_bp'), out, 'g10 keyring sig listing failed')
        # Below are disabled until we have some kind of sorting which doesn't depend on
        # readdir order
        #_, out, _ = run_proc(RNPK, ['--homedir', data_path(SECRING_G10),
        #                            '-l', '--secret'])
        #compare_file(path + 'test_stream_key_load_keys_sec', out,
        #             'g10 sec keyring key listing failed')
        #_, out, _ = run_proc(RNPK, ['--homedir', data_path(SECRING_G10),
        #                            '-l', '--secret', '--with-sigs'])
        #compare_file(path + 'test_stream_key_load_sigs_sec', out,
        #             'g10 sec keyring sig listing failed')

        _, out, _ = run_proc(RNPK, ['--homedir', KEYRING_1, '-l', '2fcadf05ffa501bb'])
        compare_file_any(allow_y2k38_on_32bit(path + 'getkey_2fcadf05ffa501bb'), out, 'list key 2fcadf05ffa501bb failed')
        _, out, _ = run_proc(RNPK, ['--homedir', KEYRING_1, '-l',
                                    '--with-sigs', '2fcadf05ffa501bb'])
        compare_file_any(allow_y2k38_on_32bit(path + 'getkey_2fcadf05ffa501bb_sig'), out, 'list sig 2fcadf05ffa501bb failed')
        _, out, _ = run_proc(RNPK, ['--homedir', KEYRING_1, '-l',
                                    '--secret', '2fcadf05ffa501bb'])
        compare_file_any(allow_y2k38_on_32bit(path + 'getkey_2fcadf05ffa501bb_sec'), out, 'list sec 2fcadf05ffa501bb failed')

        _, out, _ = run_proc(RNPK, ['--homedir', KEYRING_1, '-l', '00000000'])
        compare_file(path + 'getkey_00000000', out, 'list key 00000000 failed')
        _, out, _ = run_proc(RNPK, ['--homedir', KEYRING_1, '-l', 'zzzzzzzz'])
        compare_file(path + 'getkey_zzzzzzzz', out, 'list key zzzzzzzz failed')

        _, out, _ = run_proc(RNPK, ['--homedir', KEYRING_1, '-l', '--userid', '2fcadf05ffa501bb'])
        compare_file_any(allow_y2k38_on_32bit(path + 'getkey_2fcadf05ffa501bb'), out, 'list key 2fcadf05ffa501bb failed')

    def test_rnpkeys_g10_list_order(self):
        ret, out, _ = run_proc(RNPK, ['--homedir', data_path(SECRING_G10), '--list-keys'])
        self.assertEqual(ret, 0)
        if RNP_BRAINPOOL:
            self.assertEqual(file_text(data_path('test_cli_rnpkeys/g10_list_keys')), out, 'g10 key listing failed')
        else:
            self.assertEqual(file_text(data_path('test_cli_rnpkeys/g10_list_keys_no_bp')), out, 'g10 key listing failed')
        ret, out, _ = run_proc(RNPK, ['--homedir', data_path(SECRING_G10), '--secret', '--list-keys'])
        self.assertEqual(ret, 0)
        if RNP_BRAINPOOL:
            self.assertEqual(file_text(data_path('test_cli_rnpkeys/g10_list_keys_sec')), out, 'g10 secret key listing failed')
        else:
            self.assertEqual(file_text(data_path('test_cli_rnpkeys/g10_list_keys_sec_no_bp')), out, 'g10 secret key listing failed')

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
        params = ['--homedir', data_path('test_cli_g10_defkey/g10'),
                  '--password', PASSWORD, '--output', dst, '-s', src]
        ret, _, err = run_proc(RNP, params)
        self.assertEqual(ret, 0, 'rnp signing failed')
        # Verify signed file
        params = ['--homedir', data_path('test_cli_g10_defkey/g10'), '-v', dst]
        ret, _, err = run_proc(RNP, params)
        self.assertEqual(ret, 0, 'verification failed')
        self.assertRegex(err, RE_SIG, 'wrong rnp g10 verification output')

    def test_large_packet(self):
        # Verifying large packet file with GnuPG
        kpath = path_for_gpg(data_path(PUBRING_1))
        dpath = path_for_gpg(data_path('test_large_packet/4g.bzip2.gpg'))
        ret, _, _ = run_proc(GPG, ['--homedir', GPGHOME, '--keyring', kpath, '--verify', dpath])
        self.assertEqual(ret, 0, 'large packet verification failed')

    def test_partial_length_signature(self):
        # Verifying partial length signature with GnuPG
        kpath = path_for_gpg(data_path(PUBRING_1))
        mpath = path_for_gpg(data_path('test_partial_length/message.txt.partial-signed'))
        ret, _, _ = run_proc(GPG, ['--homedir', GPGHOME, '--keyring', kpath, '--verify', mpath])
        self.assertNotEqual(ret, 0, 'partial length signature packet should result in failure but did not')

    def test_partial_length_public_key(self):
        # Reading keyring that has a public key packet with partial length using GnuPG
        kpath = data_path('test_partial_length/pubring.gpg.partial')
        ret, _, _ = run_proc(GPG, ['--homedir', GPGHOME, '--keyring', kpath, '--list-keys'])
        self.assertNotEqual(ret, 0, 'partial length public key packet should result in failure but did not')

    def test_partial_length_zero_last_chunk(self):
        # Verifying message in partial packets having 0-size last chunk with GnuPG
        kpath = path_for_gpg(data_path(PUBRING_1))
        mpath = path_for_gpg(data_path('test_partial_length/message.txt.partial-zero-last'))
        ret, _, _ = run_proc(GPG, ['--homedir', GPGHOME, '--keyring', kpath, '--verify', mpath])
        self.assertEqual(ret, 0, 'message in partial packets having 0-size last chunk verification failed')

    def test_partial_length_largest(self):
        # Verifying message having largest possible partial packet with GnuPG
        kpath = path_for_gpg(data_path(PUBRING_1))
        mpath = path_for_gpg(data_path('test_partial_length/message.txt.partial-1g'))
        ret, _, _ = run_proc(GPG, ['--homedir', GPGHOME, '--keyring', kpath, '--verify', mpath])
        self.assertEqual(ret, 0, 'message having largest possible partial packet verification failed')

    def test_rnp_single_export(self):
        # Import key with subkeys, then export it, test that it is exported once.
        # See issue #1153
        clear_keyrings()
        # Import Alice's secret key and subkey
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--import', data_path(KEY_ALICE_SUB_SEC)])
        self.assertEqual(ret, 0, 'Alice secret key import failed')
        # Export key
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--export', 'Alice'])
        self.assertEqual(ret, 0, 'key export failed')
        pubpath = os.path.join(RNPDIR, 'Alice-export-test.asc')
        with open(pubpath, 'w+') as f:
            f.write(out)
        # List exported key packets
        params = ['--list-packets', pubpath]
        ret, out, _ = run_proc(RNP, params)
        self.assertEqual(ret, 0, PKT_LIST_FAILED)
        compare_file_ex(data_path('test_single_export_subkeys/list_key_export_single.txt'), out,
                        'exported packets mismatch')

    def test_rnp_permissive_key_import(self):
        # Import keys while skipping bad packets, see #1160
        clear_keyrings()
        # Try to import  without --permissive option, should fail.
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--import-keys', data_path('test_key_edge_cases/pubring-malf-cert.pgp')])
        self.assertNotEqual(ret, 0, 'Imported bad packets without --permissive option set!')
        # Import with --permissive
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--import-keys', '--permissive',data_path('test_key_edge_cases/pubring-malf-cert.pgp')])
        self.assertEqual(ret, 0, 'Failed to import keys with --permissive option')

        # List imported keys and sigs
        params = ['--homedir', RNPDIR, '--list-keys', '--with-sigs']
        ret, out, _ = run_proc(RNPK, params)
        self.assertEqual(ret, 0, PKT_LIST_FAILED)
        compare_file_any(allow_y2k38_on_32bit(data_path('test_cli_rnpkeys/pubring-malf-cert-permissive-import.txt')),
            out, 'listing mismatch')

    def test_rnp_list_packets(self):
        KEY_P256 = data_path('test_list_packets/ecc-p256-pub.asc')
        # List packets in humand-readable format
        params = ['--list-packets', KEY_P256]
        ret, out, _ = run_proc(RNP, params)
        self.assertEqual(ret, 0, PKT_LIST_FAILED)
        compare_file_ex(data_path('test_list_packets/list_standard.txt'), out,
                        'standard listing mismatch')
        # List packets with mpi values
        params = ['--mpi', '--list-packets', KEY_P256]
        ret, out, _ = run_proc(RNP, params)
        self.assertEqual(ret, 0, 'packet listing with mpi failed')
        compare_file_ex(data_path('test_list_packets/list_mpi.txt'), out, 'mpi listing mismatch')
        # List packets with grip/fingerprint values
        params = ['--list-packets', KEY_P256, '--grips']
        ret, out, _ = run_proc(RNP, params)
        self.assertEqual(ret, 0, 'packet listing with grips failed')
        compare_file_ex(data_path('test_list_packets/list_grips.txt'), out,
                        'grips listing mismatch')
        # List packets with raw packet contents
        params = ['--list-packets', KEY_P256, '--raw']
        ret, out, _ = run_proc(RNP, params)
        self.assertEqual(ret, 0, 'packet listing with raw packets failed')
        compare_file_ex(data_path('test_list_packets/list_raw.txt'), out, 'raw listing mismatch')
        # List packets with all options enabled
        params = ['--list-packets', KEY_P256, '--grips', '--raw', '--mpi']
        ret, out, _ = run_proc(RNP, params)
        self.assertEqual(ret, 0, 'packet listing with all options failed')
        compare_file_ex(data_path('test_list_packets/list_all.txt'), out, 'all listing mismatch')

        # List packets with JSON output
        params = ['--json', '--list-packets', KEY_P256]
        ret, out, _ = run_proc(RNP, params)
        self.assertEqual(ret, 0, 'json packet listing failed')
        compare_file_ex(data_path('test_list_packets/list_json.txt'), out, 'json listing mismatch')
        # List packets with mpi values, JSON output
        params = ['--json', '--mpi', '--list-packets', KEY_P256]
        ret, out, _ = run_proc(RNP, params)
        self.assertEqual(ret, 0, 'json mpi packet listing failed')
        compare_file_ex(data_path('test_list_packets/list_json_mpi.txt'), out,
                        'json mpi listing mismatch')
        # List packets with grip/fingerprint values, JSON output
        params = ['--json', '--grips', '--list-packets', KEY_P256]
        ret, out, _ = run_proc(RNP, params)
        self.assertEqual(ret, 0, 'json grips packet listing failed')
        compare_file_ex(data_path('test_list_packets/list_json_grips.txt'), out,
                        'json grips listing mismatch')
        # List packets with raw packet values, JSON output
        params = ['--json', '--raw', '--list-packets', KEY_P256]
        ret, out, _ = run_proc(RNP, params)
        self.assertEqual(ret, 0, 'json raw packet listing failed')
        compare_file_ex(data_path('test_list_packets/list_json_raw.txt'), out,
                        'json raw listing mismatch')
        # List packets with all values, JSON output
        params = ['--json', '--raw', '--list-packets', KEY_P256, '--mpi', '--grips']
        ret, out, err = run_proc(RNP, params)
        self.assertEqual(ret, 0, 'json all listing failed')
        compare_file_ex(data_path('test_list_packets/list_json_all.txt'), out,
                        'json all listing mismatch')
        # List packets with notations
        params = ['--list-packets', data_path('test_key_edge_cases/key-critical-notations.pgp')]
        ret, out, _ = run_proc(RNP, params)
        self.assertEqual(ret, 0)
        self.assertRegex(out, r'(?s)^.*notation data: critical text = critical value.*$')
        self.assertRegex(out, r'(?s)^.*notation data: critical binary = 0x000102030405060708090a0b0c0d0e0f \(16 bytes\).*$')
        # List packets with notations via JSON
        params = ['--list-packets', '--json', data_path('test_key_edge_cases/key-critical-notations.pgp')]
        ret, out, _ = run_proc(RNP, params)
        self.assertEqual(ret, 0)
        self.assertRegex(out, r'(?s)^.*\"human\":true.*\"name\":\"critical text\".*\"value\":\"critical value\".*$')
        self.assertRegex(out, r'(?s)^.*\"human\":false.*\"name\":\"critical binary\".*\"value\":\"000102030405060708090a0b0c0d0e0f\".*$')
        # List test file with critical notation
        params = ['--list-packets', data_path('test_messages/message.txt.signed.crit-notation')]
        ret, out, _ = run_proc(RNP, params)
        self.assertEqual(ret, 0)
        self.assertRegex(out, r'(?s)^.*:type 20, len 35, critical.*notation data: critical text = critical value.*$')

    def test_rnp_list_packets_edge_cases(self):
        KEY_EMPTY_UID = data_path('test_key_edge_cases/key-empty-uid.pgp')
        # List empty key packets
        params = ['--list-packets', data_path('test_key_edge_cases/key-empty-packets.pgp')]
        ret, out, _ = run_proc(RNP, params)
        self.assertNotEqual(ret, 0, 'packet listing not failed')
        compare_file_ex(data_path('test_key_edge_cases/key-empty-packets.txt'), out,
                        'key-empty-packets listing mismatch')
        
        # List empty key packets json
        params = ['--list-packets', '--json', data_path('test_key_edge_cases/key-empty-packets.pgp')]
        ret, _, _ = run_proc(RNP, params)
        self.assertNotEqual(ret, 0, 'packet listing not failed')

        # List empty uid
        params = ['--list-packets', KEY_EMPTY_UID]
        ret, out, _ = run_proc(RNP, params)
        self.assertEqual(ret, 0, PKT_LIST_FAILED)
        compare_file_ex(data_path('test_key_edge_cases/key-empty-uid.txt'), out,
                        'key-empty-uid listing mismatch')

        # List empty uid with raw packet contents
        params = ['--list-packets', '--raw', KEY_EMPTY_UID]
        ret, out, _ = run_proc(RNP, params)
        self.assertEqual(ret, 0, PKT_LIST_FAILED)
        compare_file_ex(data_path('test_key_edge_cases/key-empty-uid-raw.txt'), out,
                        'key-empty-uid-raw listing mismatch')

        # List empty uid packet contents to JSON
        params = ['--list-packets', '--json', KEY_EMPTY_UID]
        ret, out, _ = run_proc(RNP, params)
        self.assertEqual(ret, 0, PKT_LIST_FAILED)
        compare_file_ex(data_path('test_key_edge_cases/key-empty-uid.json'), out,
                        'key-empty-uid json listing mismatch')

        # List experimental subpackets
        params = ['--list-packets', data_path('test_key_edge_cases/key-subpacket-101-110.pgp')]
        ret, out, _ = run_proc(RNP, params)
        self.assertEqual(ret, 0, PKT_LIST_FAILED)
        compare_file_ex(data_path('test_key_edge_cases/key-subpacket-101-110.txt'), out,
                        'key-subpacket-101-110 listing mismatch')

        # List experimental subpackets JSON
        params = ['--list-packets', '--json', data_path('test_key_edge_cases/key-subpacket-101-110.pgp')]
        ret, out, _ = run_proc(RNP, params)
        self.assertEqual(ret, 0, PKT_LIST_FAILED)
        compare_file_ex(data_path('test_key_edge_cases/key-subpacket-101-110.json'), out,
                        'key-subpacket-101-110 json listing mismatch')

        # List malformed signature
        params = ['--list-packets', data_path('test_key_edge_cases/key-malf-sig.pgp')]
        ret, out, _ = run_proc(RNP, params)
        self.assertEqual(ret, 0, PKT_LIST_FAILED)
        compare_file_ex(data_path('test_key_edge_cases/key-malf-sig.txt'), out,
                        'key-malf-sig listing mismatch')

        # List malformed signature JSON
        params = ['--list-packets', '--json', data_path('test_key_edge_cases/key-malf-sig.pgp')]
        ret, out, _ = run_proc(RNP, params)
        self.assertEqual(ret, 0, PKT_LIST_FAILED)
        compare_file_ex(data_path('test_key_edge_cases/key-malf-sig.json'), out,
                        'key-malf-sig json listing mismatch')

    def test_debug_log(self):
        run_proc(RNPK, ['--homedir', data_path('keyrings/1'), '--list-keys', '--debug', '--all'])
        run_proc(RNPK, ['--homedir', data_path('keyrings/2'), '--list-keys', '--debug', '--all'])
        run_proc(RNPK, ['--homedir', data_path('keyrings/3'), '--list-keys', '--debug', '--all'])
        run_proc(RNPK, ['--homedir', data_path(SECRING_G10),
                        '--list-keys', '--debug', '--all'])

    def test_pubring_loading(self):
        NO_PUBRING = r'(?s)^.*warning: keyring at path \'.*/pubring.gpg\' doesn\'t exist.*$'
        NO_USERID = 'No userid or default key for operation'

        test_dir = tempfile.mkdtemp(prefix='rnpctmp')
        test_data = data_path(MSG_TXT)
        output = os.path.join(test_dir, 'output')
        params = ['--symmetric', '--password', 'pass', '--homedir', test_dir, test_data, '--output', output]
        ret, _, err = run_proc(RNP, ['--encrypt'] + params)
        self.assertEqual(ret, 1, 'encrypt w/o pubring didn\'t fail')
        self.assertRegex(err, NO_PUBRING, 'wrong no-keyring message')
        self.assertIn(NO_USERID, err, 'Unexpected no key output')
        self.assertIn('Failed to build recipients key list', err, 'Unexpected key list output')

        ret, _, err = run_proc(RNP, ['--sign'] + params)
        self.assertEqual(ret, 1, 'sign w/o pubring didn\'t fail')
        self.assertRegex(err, NO_PUBRING, 'wrong failure output')
        self.assertIn(NO_USERID, err, 'wrong no userid message')
        self.assertIn('Failed to build signing keys list', err, 'wrong signing list failure message')

        ret, _, err = run_proc(RNP, ['--clearsign'] + params)
        self.assertEqual(ret, 1, 'clearsign w/o pubring didn\'t fail')
        self.assertRegex(err, NO_PUBRING, 'wrong clearsign no pubring message')
        self.assertIn(NO_USERID, err, 'Unexpected clearsign no key output')
        self.assertIn('Failed to build signing keys list', err, 'Unexpected clearsign key list output')

        ret, _, _ = run_proc(RNP, params)
        self.assertEqual(ret, 0, 'symmetric w/o pubring failed')

        shutil.rmtree(test_dir)

    def test_homedir_accessibility(self):
        ret, _, _ = run_proc(RNPK, ['--homedir', os.path.join(RNPDIR, 'non-existing'), '--generate', '--password=none'])
        self.assertNotEqual(ret, 0, 'failed to check for homedir accessibility')
        os.mkdir(os.path.join(RNPDIR, 'existing'), 0o700)
        ret, _, _ = run_proc(RNPK, ['--homedir', os.path.join(RNPDIR, 'existing'), '--generate', '--password=none'])
        self.assertEqual(ret, 0, 'failed to use writeable and existing homedir')

    def test_no_home_dir(self):
        home = os.environ['HOME']
        del os.environ['HOME']
        ret, _, _ = run_proc(RNP, ['-v', 'non-existing.pgp'])
        os.environ['HOME'] = home
        self.assertEqual(ret, 2, 'failed to run without HOME env variable')

    def test_exit_codes(self):
        ret, _, _ = run_proc(RNP, ['--homedir', RNPDIR, '--help'])
        self.assertEqual(ret, 0, 'invalid exit code of \'rnp --help\'')
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--help'])
        self.assertEqual(ret, 0, 'invalid exit code of \'rnpkeys --help\'')
        ret, _, _ = run_proc(RNP, ['--homedir', RNPDIR, '--unknown-option', '--help'])
        self.assertNotEqual(ret, 0, 'rnp should return non-zero exit code for unknown command line options')
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--unknown-option', '--help'])
        self.assertNotEqual(ret, 0, 'rnpkeys should return non-zero exit code for unknown command line options')

    def test_input_from_specifier(self):
        KEY_LIST = r'(?s)^.*' \
        r'1 key found.*' \
        r'pub .*255/EdDSA.*0451409669ffde3c.*' \
        r'73edcc9119afc8e2dbbdcde50451409669ffde3c.*$'
        NO_KEY_LIST = r'(?s)^.*' \
        r'Key\(s\) not found.*$'
        WRONG_VAR = r'(?s)^.*' \
        r'Failed to get value of the environment variable \'SOMETHING_UNSET\'.*' \
        r'Failed to create input for env:SOMETHING_UNSET.*$'
        WRONG_DATA = r'(?s)^.*' \
        r'failed to import key\(s\) from env:KEY_FILE, stopping.*$'
        PGP_MSG = r'(?s)^.*' \
        r'-----BEGIN PGP MESSAGE-----.*' \
        r'-----END PGP MESSAGE-----.*$'
        ENV_KEY = 'env:KEY_FILE'

        clear_keyrings()
        # Import key from the stdin
        ktext = file_text(data_path(KEY_ALICE_SEC))
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--import', '-'], ktext)
        self.assertEqual(ret, 0, 'failed to import key from stdin')
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
        self.assertEqual(ret, 0, KEY_LIST_FAILED)
        self.assertRegex(out, KEY_LIST, KEY_LIST_WRONG)
        # Cleanup and import key from the env variable
        clear_keyrings()
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
        self.assertNotEqual(ret, 0, 'no key list failed')
        self.assertRegex(out, NO_KEY_LIST, KEY_LIST_WRONG)
        # Pass unset variable
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--import', 'env:SOMETHING_UNSET'])
        self.assertNotEqual(ret, 0, 'key import from env must fail')
        self.assertRegex(err, WRONG_VAR, 'wrong output')
        # Pass incorrect value in environment variable
        os.environ['KEY_FILE'] = "something"
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--import', ENV_KEY])
        self.assertNotEqual(ret, 0, 'key import failed')
        self.assertRegex(err, WRONG_DATA, 'wrong output')
        # Now import the correct key
        os.environ['KEY_FILE'] = ktext
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--import', ENV_KEY])
        self.assertEqual(ret, 0, 'key import failed')
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
        self.assertEqual(ret, 0, KEY_LIST_FAILED)
        self.assertRegex(out, KEY_LIST, KEY_LIST_WRONG)

        # Sign message from the stdin, using the env keyfile
        ret, out, _ = run_proc(RNP, ['-s', '-', '--password', 'password', '--armor', '--keyfile', ENV_KEY], 'Message to sign')
        self.assertEqual(ret, 0, 'Message signing failed')
        self.assertRegex(out, PGP_MSG, 'wrong signing output')
        os.environ['SIGN_MSG'] = out
        # Verify message from the env variable
        ret, out, _ = run_proc(RNP, ['-d', 'env:SIGN_MSG', '--keyfile', ENV_KEY])
        self.assertEqual(ret, 0, 'Message verification failed')
        self.assertEqual(out, 'Message to sign', 'wrong verification output')

    def test_output_to_specifier(self):
        src, enc, encasc, dec = reg_workfiles('source', '.txt', EXT_PGP, EXT_ASC, '.dec')
        with open(src, 'w+') as f:
            f.write('Hello world')
        # Encrypt file and make sure result is stored with .pgp extension
        ret, out, _ = run_proc(RNP, ['-c', src, '--password', 'password'])
        self.assertEqual(ret, 0, ENC_FAILED)
        ret, _, _ = run_proc(RNP, ['--homedir', RNPDIR, '-d', enc, '--output', dec, '--password', 'password'])
        self.assertEqual(ret, 0, DEC_FAILED)
        self.assertEqual(file_text(src), file_text(dec), DEC_DIFFERS)
        remove_files(enc, dec)
        # Encrypt file with armor and make sure result is stored with .asc extension
        ret, _, _ = run_proc(RNP, ['-c', src, '--armor', '--password', 'password'])
        self.assertEqual(ret, 0, ENC_FAILED)
        ret, out, _ = run_proc(RNP, ['--homedir', RNPDIR, '-d', encasc, '--output', '-', '--password', 'password'])
        self.assertEqual(ret, 0, DEC_FAILED)
        self.assertEqual(file_text(src), out, DEC_DIFFERS)
        remove_files(encasc)
        # Encrypt file and write result to the stdout
        ret, out, _ = run_proc(RNP, ['-c', src, '--armor', '--output', '-', '--password', 'password'])
        self.assertEqual(ret, 0, ENC_FAILED)
        ret, _, _ = run_proc(RNP, ['--homedir', RNPDIR, '-d', '--output', dec, '--password', 'password', '-'], out)
        self.assertEqual(ret, 0, DEC_FAILED)
        self.assertEqual(file_text(src), file_text(dec), DEC_DIFFERS)
        remove_files(dec)
        # Encrypt file and write armored result to the stdout
        ret, out, _ = run_proc(RNP, ['-c', src, '--armor','--output', '-', '--password', 'password'])
        self.assertEqual(ret, 0, ENC_FAILED)
        ret, out, _ = run_proc(RNP, ['--homedir', RNPDIR, '-d', '--output', '-', '--password', 'password', '-'], out)
        self.assertEqual(ret, 0, DEC_FAILED)
        self.assertEqual(file_text(src), out, DEC_DIFFERS)
        # Encrypt stdin and write result to the stdout
        srctxt = file_text(src)
        ret, out, _ = run_proc(RNP, ['-c', '--armor', '--password', 'password'], srctxt)
        self.assertEqual(ret, 0, ENC_FAILED)
        ret, out, _ = run_proc(RNP, ['--homedir', RNPDIR, '-d', '--password', 'password'], out)
        self.assertEqual(ret, 0, DEC_FAILED)
        self.assertEqual(out, srctxt, DEC_DIFFERS)
        # Encrypt stdin and attempt to write to non-existing dir
        ret, _, err = run_proc(RNP, ['-c', '--armor', '--password', 'password', '--output', 'nonexisting/output.pgp'], srctxt)
        self.assertNotEqual(ret, 0)
        self.assertRegex(err, r'(?s)^.*init_file_dest.*failed to create file.*output.pgp.*Error 2.*$')
        self.assertNotRegex(err, r'(?s)^.*failed to initialize encryption.*$')
        self.assertRegex(err, r'(?s)^.*failed to open source or create output.*$')
        # Sign stdin and then verify it using non-existing directory for output
        ret, out, _ = run_proc(RNP, ['--homedir', RNPDIR, '--armor', '--password', 'password', '-s'], srctxt)
        self.assertEqual(ret, 0)
        self.assertRegex(out, r'(?s)^.*BEGIN PGP MESSAGE.*END PGP MESSAGE.*$')
        ret, _, err = run_proc(RNP, ['--homedir', RNPDIR, '-v', '--output', 'nonexisting/output.pgp'], out)
        self.assertEqual(ret, 1)
        self.assertRegex(err, r'(?s)^.*init_file_dest.*failed to create file.*output.pgp.*Error 2.*$')

    def test_empty_keyrings(self):
        NO_KEYRING = r'(?s)^.*' \
        r'warning: keyring at path \'.*/\.rnp/pubring.gpg\' doesn\'t exist.*' \
        r'warning: keyring at path \'.*/\.rnp/secring.gpg\' doesn\'t exist.*$'
        EMPTY_KEYRING = r'(?s)^.*' \
        r'warning: no keys were loaded from the keyring \'.*/\.rnp/pubring.gpg\'.*' \
        r'warning: no keys were loaded from the keyring \'.*/\.rnp/secring.gpg\'.*$'
        PUB_IMPORT= r'(?s)^.*pub\s+255/EdDSA 0451409669ffde3c .* \[SC\].*$'
        EMPTY_SECRING = r'(?s)^.*' \
        r'warning: no keys were loaded from the keyring \'.*/\.rnp/secring.gpg\'.*$'
        SEC_IMPORT= r'(?s)^.*sec\s+255/EdDSA 0451409669ffde3c .* \[SC\].*$'

        os.rename(RNPDIR, RNPDIR + '-old')
        home = os.environ['HOME']
        os.environ['HOME'] = WORKDIR
        try:
            self.assertFalse(os.path.isdir(RNPDIR), '.rnp directory should not exists')
            src, enc, dec = reg_workfiles('source', '.txt', EXT_PGP, '.dec')
            random_text(src, 2000)
            # Run symmetric encryption/decryption without .rnp home directory
            ret, _, err = run_proc(RNP, ['-c', src, '--password', 'password'])
            self.assertEqual(ret, 0, 'Symmetric encryption without home failed')
            self.assertNotRegex(err, NO_KEYRING, 'No keyring msg in encryption output')
            ret, _, err = run_proc(RNP, ['-d', enc, '--password', 'password', '--output', dec])
            self.assertEqual(ret, 0, 'Symmetric decryption without home failed')
            self.assertRegex(err, NO_KEYRING, 'No keyring msg in decryption output')
            self.assertIn(WORKDIR, err, 'No workdir in decryption output')
            compare_files(src, dec, DEC_DIFFERS)
            remove_files(enc, dec)
            # Import key without .rnp home directory
            ret, out, err = run_proc(RNPK, ['--import', data_path(KEY_ALICE_PUB)])
            self.assertEqual(ret, 0, 'Key import failed without home')
            self.assertRegex(err, NO_KEYRING, 'No keyring msg in key import output')
            self.assertIn(WORKDIR, err, 'No workdir in key import output')
            self.assertRegex(out, PUB_IMPORT, 'Wrong key import output')
            ret, out, err = run_proc(RNPK, ['--import', data_path(KEY_ALICE_SEC)])
            self.assertEqual(ret, 0, 'Secret key import without home failed')
            self.assertNotRegex(err, NO_KEYRING, 'no keyring message in key import output')
            self.assertRegex(err, EMPTY_SECRING, 'no empty secrin in key import output')
            self.assertIn(WORKDIR, err, 'no workdir in key import output')
            self.assertRegex(out, SEC_IMPORT, 'Wrong secret key import output')
            # Run with empty .rnp home directory
            shutil.rmtree(RNPDIR, ignore_errors=True)
            os.mkdir(RNPDIR, 0o700)
            ret, _, err = run_proc(RNP, ['-c', src, '--password', 'password'])
            self.assertEqual(ret, 0)
            self.assertNotRegex(err, NO_KEYRING)
            ret, out, err = run_proc(RNP, ['-d', enc, '--password', 'password', '--output', dec])
            self.assertEqual(ret, 0, 'Symmetric decryption failed')
            self.assertRegex(err, NO_KEYRING, 'No keyring message in decryption output')
            self.assertIn(WORKDIR, err, 'No workdir in decryption output')
            compare_files(src, dec, DEC_DIFFERS)
            remove_files(enc, dec)
            # Import key with empty .rnp home directory
            ret, out, err = run_proc(RNPK, ['--import', data_path(KEY_ALICE_PUB)])
            self.assertEqual(ret, 0, 'Public key import with empty home failed')
            self.assertRegex(err, NO_KEYRING, 'No keyring message in key import output')
            self.assertIn(WORKDIR, err, 'No workdir in key import output')
            self.assertRegex(out, PUB_IMPORT, 'Wrong pub key import output')
            ret, out, err = run_proc(RNPK, ['--import', data_path(KEY_ALICE_SEC)])
            self.assertEqual(ret, 0, 'Secret key import failed')
            self.assertNotRegex(err, NO_KEYRING, 'No-keyring message in secret key import output')
            self.assertRegex(err, EMPTY_SECRING, 'No empty secring msg in secret key import output')
            self.assertIn(WORKDIR, err, 'No workdir in secret key import output')
            self.assertRegex(out, SEC_IMPORT, 'wrong secret key import output')
            # Run with .rnp home directory with empty keyrings
            shutil.rmtree(RNPDIR, ignore_errors=True)
            os.mkdir(RNPDIR, 0o700)
            random_text(os.path.join(RNPDIR, PUBRING), 0)
            random_text(os.path.join(RNPDIR, SECRING), 0)
            ret, out, err = run_proc(RNP, ['-c', src, '--password', 'password'])
            self.assertEqual(ret, 0, 'Symmetric encryption failed')
            self.assertNotRegex(err, EMPTY_KEYRING, 'Invalid encryption output')
            ret, out, err = run_proc(RNP, ['-d', enc, '--password', 'password', '--output', dec])
            self.assertEqual(ret, 0, 'Symmetric decryption failed')
            self.assertRegex(err, EMPTY_KEYRING, 'wrong decryption output')
            self.assertIn(WORKDIR, err, 'wrong decryption output')
            compare_files(src, dec, DEC_DIFFERS)
            remove_files(enc, dec)
            # Import key with empty keyrings in .rnp home directory
            ret, out, err = run_proc(RNPK, ['--import', data_path(KEY_ALICE_PUB)])
            self.assertEqual(ret, 0, 'Public key import failed')
            self.assertRegex(err, EMPTY_KEYRING, 'No empty keyring msg in key import output')
            self.assertIn(WORKDIR, err, 'No workdir in empty keyring key import output')
            self.assertRegex(out, PUB_IMPORT, 'Wrong pubkey import output')
            ret, out, err = run_proc(RNPK, ['--import', data_path(KEY_ALICE_SEC)])
            self.assertEqual(ret, 0, 'Secret key import failed')
            self.assertNotRegex(err, EMPTY_KEYRING, 'No empty keyring in key import output')
            self.assertRegex(err, EMPTY_SECRING, 'No empty secring in key import output')
            self.assertIn(WORKDIR, err, 'wrong key import output')
            self.assertRegex(out, SEC_IMPORT, 'wrong secret key import output')
        finally:
            os.environ['HOME'] = home
            shutil.rmtree(RNPDIR, ignore_errors=True)
            os.rename(RNPDIR + '-old', RNPDIR)
            clear_workfiles()

    def test_alg_aliases(self):
        src, enc = reg_workfiles('source', '.txt', EXT_PGP)
        with open(src, 'w+') as f:
            f.write('Hello world')
        # Encrypt file but forget to pass cipher name
        ret, _, err = run_proc(RNP, ['-c', src, '--password', 'password', '--cipher'])
        self.assertNotEqual(ret, 0)
        # Encrypt file using the unknown symmetric algorithm
        ret, _, err = run_proc(RNP, ['-c', src, '--cipher', 'bad', '--password', 'password'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(err, r'(?s)^.*Unsupported encryption algorithm: bad.*$')
        # Encrypt file but forget to pass hash algorithm name
        ret, _, err = run_proc(RNP, ['-c', src, '--password', 'password', '--hash'])
        self.assertNotEqual(ret, 0)
        # Encrypt file using the unknown hash algorithm
        ret, _, err = run_proc(RNP, ['-c', src, '--hash', 'bad', '--password', 'password'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(err, r'(?s)^.*Unsupported hash algorithm: bad.*$')
        # Encrypt file using the AES algorithm instead of AES-128
        ret, _, err = run_proc(RNP, ['-c', src, '--cipher', 'AES', '--password', 'password'])
        self.assertEqual(ret, 0)
        self.assertNotRegex(err, r'(?s)^.*Warning, unsupported encryption algorithm: AES.*$')
        self.assertNotRegex(err, r'(?s)^.*Unsupported encryption algorithm: AES.*$')
        # Make sure AES-128 was used
        ret, out, _ = run_proc(RNP, ['--list-packets', enc])
        self.assertEqual(ret, 0)
        self.assertRegex(out,r'(?s)^.*Symmetric-key encrypted session key packet.*symmetric algorithm: 7 \(AES-128\).*$')
        remove_files(enc)
        # Encrypt file using the 3DES instead of tripledes
        ret, _, err = run_proc(RNP, ['-c', src, '--cipher', '3DES', '--password', 'password'])
        self.assertEqual(ret, 0)
        self.assertNotRegex(err, r'(?s)^.*Warning, unsupported encryption algorithm: 3DES.*$')
        self.assertNotRegex(err, r'(?s)^.*Unsupported encryption algorithm: 3DES.*$')
        # Make sure 3DES was used
        ret, out, _ = run_proc(RNP, ['--list-packets', enc])
        self.assertEqual(ret, 0)
        self.assertRegex(out,r'(?s)^.*Symmetric-key encrypted session key packet.*symmetric algorithm: 2 \(TripleDES\).*$')
        remove_files(enc)
        # Use ripemd-160 hash instead of RIPEMD160
        ret, _, err = run_proc(RNP, ['-c', src, '--hash', 'ripemd-160', '--password', 'password'])
        self.assertEqual(ret, 0)
        self.assertNotRegex(err, r'(?s)^.*Unsupported hash algorithm: ripemd-160.*$')
        # Make sure RIPEMD160 was used
        ret, out, _ = run_proc(RNP, ['--list-packets', enc])
        self.assertEqual(ret, 0)
        self.assertRegex(out,r'(?s)^.*Symmetric-key encrypted session key packet.*s2k hash algorithm: 3 \(RIPEMD160\).*$')
        remove_files(enc)

    def test_core_dumps(self):
        CORE_DUMP = r'(?s)^.*warning: core dumps may be enabled, sensitive data may be leaked to disk.*$'
        NO_CORE_DUMP = r'(?s)^.*warning: --coredumps doesn\'t make sense on windows systems.*$'
        # Check rnpkeys for the message
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
        self.assertEqual(ret, 0)
        self.assertNotRegex(err, CORE_DUMP)
        # Check rnp for the message
        ret, _, err = run_proc(RNP, ['--homedir', RNPDIR, '--armor', '--password', 'password', '-c'], 'message')
        self.assertEqual(ret, 0)
        self.assertNotRegex(err, CORE_DUMP)
        # Enable coredumps for rnpkeys
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys', '--coredumps'])
        self.assertEqual(ret, 0)
        if is_windows():
            self.assertNotRegex(err, CORE_DUMP)
            self.assertRegex(err, NO_CORE_DUMP)
        else:
            self.assertRegex(err, CORE_DUMP)
            self.assertNotRegex(err, NO_CORE_DUMP)
        # Enable coredumps for rnp
        ret, _, err = run_proc(RNP, ['--homedir', RNPDIR, '--armor', '--password', 'password', '-c', '--coredumps'], 'message')
        self.assertEqual(ret, 0)
        if is_windows():
            self.assertNotRegex(err, CORE_DUMP)
            self.assertRegex(err, NO_CORE_DUMP)
        else:
            self.assertRegex(err, CORE_DUMP)
            self.assertNotRegex(err, NO_CORE_DUMP)

    def test_backend_version(self):
        BOTAN_BACKEND_VERSION = r'(?s)^.*.' \
        'Backend: Botan.*' \
        'Backend version: ([a-zA-z\.0-9]+).*$'
        OPENSSL_BACKEND_VERSION = r'(?s)^.*' \
        'Backend: OpenSSL.*' \
        'Backend version: ([a-zA-z\.0-9]+).*$'
        # Run without parameters and make sure it matches
        ret, out, _ = run_proc(RNP, [])
        self.assertNotEqual(ret, 0)
        match = re.match(BOTAN_BACKEND_VERSION, out) or re.match(OPENSSL_BACKEND_VERSION, out)
        self.assertTrue(match)
        # Run with version parameters
        ret, out, _ = run_proc(RNP, ['--version'])
        self.assertEqual(ret, 0)
        match = re.match(BOTAN_BACKEND_VERSION, out)
        backend_prog = 'botan'
        if not match:
            match = re.match(OPENSSL_BACKEND_VERSION, out)
            backend_prog = 'openssl'
        self.assertTrue(match)
        # check that botan or openssl executable binary exists in $PATH
        backen_prog_ext = shutil.which(backend_prog)
        if backen_prog_ext is not None:
            ret, out, _ = run_proc(backen_prog_ext, ['version'])
            self.assertEqual(ret, 0)
            self.assertIn(match.group(1), out)

    def test_wrong_mpi_bit_count(self):
        WRONG_MPI_BITS = r'(?s)^.*Warning! Wrong mpi bit count: got [0-9]+, but actual is [0-9]+.*$'
        # Make sure message is not displayed on normal keys
        ret, _, err = run_proc(RNP, ['--list-packets', data_path(PUBRING_1)])
        self.assertEqual(ret, 0)
        self.assertNotRegex(err, WRONG_MPI_BITS)
        # Make sure message is displayed on wrong mpi
        ret, _, err = run_proc(RNP, ['--list-packets', data_path('test_key_edge_cases/alice-wrong-mpi-bit-count.pgp')])
        self.assertEqual(ret, 0)
        self.assertRegex(err, WRONG_MPI_BITS)

    def test_eddsa_small_x(self):
        os.rename(RNPDIR, RNPDIR + '-old')
        home = os.environ['HOME']
        os.environ['HOME'] = WORKDIR
        try:
            self.assertFalse(os.path.isdir(RNPDIR), '.rnp directory should not exists')
            src, sig, ver = reg_workfiles('source', '.txt', EXT_PGP, '.dec')
            random_text(src, 2000)
            # load just public key and verify pre-signed message
            ret, _, _ = run_proc(RNPK, ['--import', data_path('test_key_edge_cases/key-eddsa-small-x-pub.asc')])
            self.assertEqual(ret, 0)
            ret, _, err = run_proc(RNP, ['--verify', data_path('test_messages/message.txt.sign-small-eddsa-x')])
            self.assertEqual(ret, 0)
            self.assertRegex(err, r'(?s)^.*Good signature made .*using EdDSA key 7bc55b9bdce36e18.*$')
            # load secret key and sign message
            ret, out, _ = run_proc(RNPK, ['--import', data_path('test_key_edge_cases/key-eddsa-small-x-sec.asc')])
            self.assertEqual(ret, 0)
            self.assertRegex(out, r'(?s)^.*sec.*255/EdDSA.*7bc55b9bdce36e18.*eddsa_small_x.*ssb.*c6c35ea115368a0b.*$')
            ret, _, _ = run_proc(RNP, ['--password', PASSWORD, '--sign', src, '--output', sig])
            self.assertEqual(ret, 0)
            # verify back
            ret, _, err = run_proc(RNP, ['--verify', sig, '--output', ver])
            self.assertEqual(ret, 0)
            self.assertEqual(file_text(src), file_text(ver))
            self.assertRegex(err, r'(?s)^.*Good signature made .*using EdDSA key 7bc55b9bdce36e18.*$')
            # verify back with GnuPG
            os.remove(ver)
            gpg_import_pubring(data_path('test_key_edge_cases/key-eddsa-small-x-pub.asc'))
            gpg_verify_file(sig, ver, 'eddsa_small_x')
        finally:
            os.environ['HOME'] = home
            shutil.rmtree(RNPDIR, ignore_errors=True)
            os.rename(RNPDIR + '-old', RNPDIR)
            clear_workfiles()
    
    def test_cv25519_bit_fix(self):
        RE_NOT_25519 = r'(?s)^.*Error: specified key is not Curve25519 ECDH subkey.*$'
        # Import and tweak non-protected secret key
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--import', data_path(KEY_25519_NOTWEAK_SEC)])
        self.assertEqual(ret, 0)
        # Check some --edit-key invalid options combinations
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--edit-key'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(err, r'(?s)^.*You need to specify a key or subkey to edit.*$')
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--edit-key', '3176fc1486aa2528'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(err, r'(?s)^.*You should specify at least one editing option for --edit-key.*$')
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--edit-key', '--check-cv25519-bits'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(err, r'(?s)^.*You need to specify a key or subkey to edit.*$')
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--edit-key', '--check-cv25519-bits', 'key'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(err, r'(?s)^.*Secret keys matching \'key\' not found.*$')
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--edit-key', '--check-cv25519-bits', 'eddsa-25519-non-tweaked'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(err, RE_NOT_25519)
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--edit-key', '--check-cv25519-bits', '3176fc1486aa2528'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(err, RE_NOT_25519)
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--notty', '--edit-key', '--check-cv25519-bits', '950ee0cd34613dba'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(out, r'(?s)^.*Warning: Cv25519 key bits need fixing.*$')
        # Tweak bits
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--edit-key', '--fix-cv25519-bits', '3176fc1486aa2528'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(err, RE_NOT_25519)
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--edit-key', '--fix-cv25519-bits', '950ee0cd34613dba'])
        self.assertEqual(ret, 0)
        # Make sure bits are correctly tweaked and key may be used to decrypt and imported to GnuPG
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--notty', '--edit-key', '--check-cv25519-bits', '950ee0cd34613dba'])
        self.assertEqual(ret, 0)
        self.assertRegex(out, r'(?s)^.*Cv25519 key bits are set correctly and do not require fixing.*$')
        ret, _, _ = run_proc(RNP, ['--homedir', RNPDIR, '-d', data_path(MSG_ES_25519)])
        self.assertEqual(ret, 0)
        ret, _, _ = run_proc(GPG, ['--batch', '--homedir', GPGHOME, '--import', os.path.join(RNPDIR, SECRING)])
        self.assertEqual(ret, 0)
        ret, _, _ = run_proc(GPG, ['--batch', '--homedir', GPGHOME, '-d', data_path(MSG_ES_25519)])
        self.assertEqual(ret, 0)
        # Remove key
        ret, _, _ = run_proc(GPG, ['--batch', '--homedir', GPGHOME, '--yes', '--delete-secret-key', 'dde0ee539c017d2bd3f604a53176fc1486aa2528'])
        self.assertEqual(ret, 0)
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--remove-key', '--force', 'dde0ee539c017d2bd3f604a53176fc1486aa2528'])
        self.assertEqual(ret, 0)
        # Make sure protected secret key works the same way
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--import', data_path('test_key_edge_cases/key-25519-non-tweaked-sec-prot.asc')])
        self.assertEqual(ret, 0)
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--password', 'wrong', '--edit-key', '--check-cv25519-bits', '950ee0cd34613dba'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(err, r'(?s)^.*Error: failed to unlock key. Did you specify valid password\\?.*$')
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--password', 'password', '--notty', '--edit-key', '--check-cv25519-bits', '950ee0cd34613dba'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(out, r'(?s)^.*Warning: Cv25519 key bits need fixing.*$')
        # Tweak bits
        ret, _, err = run_proc(RNPK, ['--homedir', RNPDIR, '--password', 'wrong', '--edit-key', '--fix-cv25519-bits', '950ee0cd34613dba'])
        self.assertNotEqual(ret, 0)
        self.assertRegex(err, r'(?s)^.*Error: failed to unlock key. Did you specify valid password\\?.*$')
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--password', 'password', '--edit-key', '--fix-cv25519-bits', '950ee0cd34613dba'])
        self.assertEqual(ret, 0)
        # Make sure key is protected with the same options
        ret, out, _ = run_proc(RNP, ['--list-packets', os.path.join(RNPDIR, SECRING)])
        self.assertEqual(ret, 0)
        self.assertRegex(out, r'(?s)^.*Secret subkey packet.*254.*AES-256.*3.*SHA256.*58720256.*0x950ee0cd34613dba.*$')
        # Make sure bits are correctly tweaked and key may be used to decrypt and imported to GnuPG
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--notty', '--password', 'password', '--edit-key', '--check-cv25519-bits', '950ee0cd34613dba'])
        self.assertEqual(ret, 0)
        self.assertRegex(out, r'(?s)^.*Cv25519 key bits are set correctly and do not require fixing.*$')
        ret, _, _ = run_proc(RNP, ['--homedir', RNPDIR, '--password', 'password', '-d', data_path(MSG_ES_25519)])
        self.assertEqual(ret, 0)
        ret, _, _ = run_proc(GPG, ['--batch', '--homedir', GPGHOME, '--batch', '--passphrase', 'password', '--import', os.path.join(RNPDIR, SECRING)])
        self.assertEqual(ret, 0)
        ret, _, _ = run_proc(GPG, ['--batch', '--homedir', GPGHOME, GPG_LOOPBACK, '--batch', '--passphrase', 'password',
                                   '--trust-model', 'always', '-d', data_path(MSG_ES_25519)])
        self.assertEqual(ret, 0)
        # Remove key
        ret, _, _ = run_proc(GPG, ['--batch', '--homedir', GPGHOME, '--yes', '--delete-secret-key', 'dde0ee539c017d2bd3f604a53176fc1486aa2528'])
        self.assertEqual(ret, 0)
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--remove-key', '--force', 'dde0ee539c017d2bd3f604a53176fc1486aa2528'])
        self.assertEqual(ret, 0)
    
    def test_aead_last_chunk_zero_length(self):
        # Cover case with last AEAD chunk of the zero size
        os.rename(RNPDIR, RNPDIR + '-old')
        os.mkdir(RNPDIR)
        try:
            dec, enc = reg_workfiles('cleartext', '.dec', '.enc')
            srctxt = data_path('test_messages/message.aead-last-zero-chunk.txt')
            srcenc = data_path('test_messages/message.aead-last-zero-chunk.enc')
            # Import Alice's key
            ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--import', data_path('test_key_validity/alice-sub-sec.pgp')])
            self.assertEqual(ret, 0)
            # Decrypt already existing file
            if RNP_AEAD:
                ret, _, _ = run_proc(RNP, ['--homedir', RNPDIR, '--password', PASSWORD, '-d', srcenc, '--output', dec])
                self.assertEqual(ret, 0)
                self.assertEqual(file_text(srctxt), file_text(dec))
                os.remove(dec)
            # Decrypt with gnupg
            if GPG_AEAD:
                ret, _, _ = run_proc(GPG, ['--batch', '--passphrase', PASSWORD, '--homedir',
                                        GPGHOME, '--import', data_path('test_key_validity/alice-sub-sec.pgp')])
                self.assertEqual(ret, 0, 'gpg key import failed')
                gpg_decrypt_file(srcenc, dec, PASSWORD)
                self.assertEqual(file_text(srctxt), file_text(dec))
                os.remove(dec)
            if RNP_AEAD:
                # Encrypt with RNP
                ret, _, _ = run_proc(RNP, ['--homedir', RNPDIR, '--password', PASSWORD, '-z', '0', '-r', 'alice', '--aead=eax', '--aead-chunk-bits=1', '-e', srctxt, '--output', enc])
                self.assertEqual(ret, 0)
                # Decrypt with RNP again
                ret, _, _ = run_proc(RNP, ['--homedir', RNPDIR, '--password', PASSWORD, '-d', enc, '--output', dec])
                self.assertEqual(file_text(srctxt), file_text(dec))
                os.remove(dec)
                if GPG_AEAD:
                    # Decrypt with GnuPG
                    gpg_decrypt_file(enc, dec, PASSWORD)
                    self.assertEqual(file_text(srctxt), file_text(dec))
        finally:
            shutil.rmtree(RNPDIR, ignore_errors=True)
            os.rename(RNPDIR + '-old', RNPDIR)
            clear_workfiles()

class Encryption(unittest.TestCase):
    '''
        Things to try later:
        - different public key algorithms
        - different hash algorithms where applicable

        TODO:
        Tests in this test case should be split into many algorithm-specific tests
        (potentially auto generated)
        Reason being - if you have a problem with BLOWFISH size 1000000, you don't want
        to wait until everything else gets
        tested before your failing BLOWFISH
    '''
    # Ciphers list tro try during encryption. None will use default
    CIPHERS = [None, 'AES', 'AES192', 'AES256', 'TWOFISH', 'CAMELLIA128', 'CAMELLIA192',
               'CAMELLIA256', 'IDEA', '3DES', 'CAST5', 'BLOWFISH']
    SIZES = [20, 40, 120, 600, 1000, 5000, 20000, 250000]
    # Compression parameters to try during encryption(s)
    Z = [[None, 0], ['zip'], ['zlib'], ['bzip2'], [None, 1], [None, 9]]
    # Number of test runs - each run picks next encryption algo and size, wrapping on array
    RUNS = 20

    @classmethod
    def setUpClass(cls):
        # Generate keypair in RNP
        rnp_genkey_rsa(KEY_ENCRYPT)
        # Add some other keys to the keyring
        rnp_genkey_rsa('dummy1@rnp', 1024)
        rnp_genkey_rsa('dummy2@rnp', 1024)
        gpg_import_pubring()
        gpg_import_secring()
        if not RNP_TWOFISH:
            Encryption.CIPHERS.remove('TWOFISH')
        Encryption.CIPHERS_R = list_upto(Encryption.CIPHERS, Encryption.RUNS)
        Encryption.SIZES_R = list_upto(Encryption.SIZES, Encryption.RUNS)
        Encryption.Z_R = list_upto(Encryption.Z, Encryption.RUNS)

    @classmethod
    def tearDownClass(cls):
        clear_keyrings()

    def tearDown(self):
        clear_workfiles()

    # Encrypt cleartext file with GPG and decrypt it with RNP,
    # using different ciphers and file sizes
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
        if not RNP_AEAD:
            print('AEAD is not available for RNP - skipping.')
            return
        CIPHERS = ['AES', 'AES192', 'AES256', 'TWOFISH', 'CAMELLIA128', 'CAMELLIA192', 'CAMELLIA256']
        if not RNP_TWOFISH:
            CIPHERS.remove('TWOFISH')
        AEAD_C = list_upto(CIPHERS, Encryption.RUNS)
        AEAD_M = list_upto([None, 'eax', 'ocb'], Encryption.RUNS)
        AEAD_B = list_upto([None, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 16], Encryption.RUNS)

        # Encrypt and decrypt cleartext using the AEAD
        for size, cipher, aead, bits, z in zip(Encryption.SIZES_R, AEAD_C,
                                               AEAD_M, AEAD_B, Encryption.Z_R):
            rnp_sym_encryption_rnp_aead(size, cipher, z, [aead, bits], GPG_AEAD)

    def test_encryption_multiple_recipients(self):
        USERIDS = ['key1@rnp', 'key2@rnp', 'key3@rnp']
        KEYPASS = ['key1pass', 'key2pass', 'key3pass']
        PASSWORDS = ['password1', 'password2', 'password3']
        # Generate multiple keys and import to GnuPG
        for uid, pswd in zip(USERIDS, KEYPASS):
            rnp_genkey_rsa(uid, 1024, pswd)

        gpg_import_pubring()
        gpg_import_secring()

        KEYPSWD = tuple((t1, t2) for t1 in range(len(USERIDS) + 1)
                        for t2 in range(len(PASSWORDS) + 1))
        KEYPSWD = list_upto(KEYPSWD, Encryption.RUNS)
        if GPG_AEAD and RNP_AEAD:
            AEADS = list_upto([None, [None], ['eax'], ['ocb']], Encryption.RUNS)
        else:
            AEADS = list_upto([None], Encryption.RUNS)

        src, dst, dec = reg_workfiles('cleartext', '.txt', '.rnp', '.dec')
        # Generate random file of required size
        random_text(src, 65500)

        for kpswd, aead in zip(KEYPSWD, AEADS):
            keynum, pswdnum = kpswd
            if (keynum == 0) and (pswdnum == 0):
                continue
            # For CFB mode there is ~5% probability that GnuPG will attempt to decrypt 
            # message's SESK with a wrong password, see T3795 on dev.gnupg.org
            skipgpg = not aead and ((pswdnum > 1) or ((pswdnum > 0) and (keynum > 0)))
            uids = USERIDS[:keynum] if keynum else None
            pswds = PASSWORDS[:pswdnum] if pswdnum else None

            rnp_encrypt_file_ex(src, dst, uids, pswds, aead)

            # Decrypt file with each of the keys, we have different password for each key
            for pswd in KEYPASS[:keynum]:
                if not skipgpg:
                    gpg_decrypt_file(dst, dec, pswd)
                    gpg_agent_clear_cache()
                    remove_files(dec)
                rnp_decrypt_file(dst, dec, '\n'.join([pswd] * 5))
                remove_files(dec)

            # Decrypt file with each of the passwords (with gpg only first password is checked)
            if skipgpg:
                gpg_decrypt_file(dst, dec, PASSWORDS[0])
                gpg_agent_clear_cache()
                remove_files(dec)

            for pswd in PASSWORDS[:pswdnum]:
                rnp_decrypt_file(dst, dec, '\n'.join([pswd] * 5))
                remove_files(dec)

            remove_files(dst, dec)

        clear_workfiles()

    def test_encryption_and_signing(self):
        USERIDS = ['enc-sign1@rnp', 'enc-sign2@rnp', 'enc-sign3@rnp']
        KEYPASS = ['encsign1pass', 'encsign2pass', 'encsign3pass']
        PASSWORDS = ['password1', 'password2', 'password3']
        CIPHERS = ['AES', 'AES192', 'AES256', 'TWOFISH', 'CAMELLIA128', 'CAMELLIA192', 'CAMELLIA256']
        if not RNP_TWOFISH:
            CIPHERS.remove('TWOFISH')
        AEAD_C = list_upto(CIPHERS, Encryption.RUNS)
        # Generate multiple keys and import to GnuPG
        for uid, pswd in zip(USERIDS, KEYPASS):
            rnp_genkey_rsa(uid, 1024, pswd)

        gpg_import_pubring()
        gpg_import_secring()

        SIGNERS = list_upto(range(1, len(USERIDS) + 1), Encryption.RUNS)
        KEYPSWD = tuple((t1, t2) for t1 in range(1, len(USERIDS) + 1)
                        for t2 in range(len(PASSWORDS) + 1))
        KEYPSWD = list_upto(KEYPSWD, Encryption.RUNS)
        if GPG_AEAD and RNP_AEAD:
            AEADS = list_upto([None, [None], ['eax'], ['ocb']], Encryption.RUNS)
        else:
            AEADS = list_upto([None], Encryption.RUNS)
        ZS = list_upto([None, [None, 0]], Encryption.RUNS)

        src, dst, dec = reg_workfiles('cleartext', '.txt', '.rnp', '.dec')
        # Generate random file of required size
        random_text(src, 65500)

        for i in range(0, Encryption.RUNS):
            signers = USERIDS[:SIGNERS[i]]
            signpswd = KEYPASS[:SIGNERS[i]]
            keynum, pswdnum = KEYPSWD[i]
            recipients = USERIDS[:keynum]
            passwords = PASSWORDS[:pswdnum]
            aead = AEADS[i]
            z = ZS[i]
            cipher = AEAD_C[i]
            # For CFB mode there is ~5% probability that GnuPG will attempt to decrypt 
            # message's SESK with a wrong password, see T3795 on dev.gnupg.org
            skipgpg = not aead and ((pswdnum > 1) or ((pswdnum > 0) and (keynum > 0)))

            rnp_encrypt_and_sign_file(src, dst, recipients, passwords, signers,
                                      signpswd, aead, cipher, z)
            # Decrypt file with each of the keys, we have different password for each key


            for pswd in KEYPASS[:keynum]:
                if not skipgpg:
                    gpg_decrypt_file(dst, dec, pswd)
                    gpg_agent_clear_cache()
                    remove_files(dec)
                rnp_decrypt_file(dst, dec, '\n'.join([pswd] * 5))
                remove_files(dec)

            # GPG decrypts only with first password, see T3795
            if skipgpg and pswdnum:
                gpg_decrypt_file(dst, dec, PASSWORDS[0])
                gpg_agent_clear_cache()
                remove_files(dec)

            # Decrypt file with each of the passwords
            for pswd in PASSWORDS[:pswdnum]:
                if not skipgpg:
                    gpg_decrypt_file(dst, dec, pswd)
                    gpg_agent_clear_cache()
                    remove_files(dec)
                rnp_decrypt_file(dst, dec, '\n'.join([pswd] * 5))
                remove_files(dec)

            remove_files(dst, dec)

    def test_encryption_weird_userids_special_1(self):
        uid = WEIRD_USERID_SPECIAL_CHARS
        pswd = 'encSpecial1Pass'
        rnp_genkey_rsa(uid, 1024, pswd)
        # Encrypt
        src = data_path(MSG_TXT)
        dst, dec = reg_workfiles('weird_userids_special_1', '.rnp', '.dec')
        rnp_encrypt_file_ex(src, dst, [uid], None, None) 
        # Decrypt
        rnp_decrypt_file(dst, dec, pswd)
        compare_files(src, dec, RNP_DATA_DIFFERS)
        clear_workfiles()

    def test_encryption_weird_userids_special_2(self):
        USERIDS = [WEIRD_USERID_SPACE, WEIRD_USERID_QUOTE, WEIRD_USERID_SPACE_AND_QUOTE, WEIRD_USERID_QUOTE_AND_SPACE]
        KEYPASS = ['encSpecial2Pass1', 'encSpecial2Pass2', 'encSpecial2Pass3', 'encSpecial2Pass4']
        # Generate multiple keys
        for uid, pswd in zip(USERIDS, KEYPASS):
            rnp_genkey_rsa(uid, 1024, pswd)
        # Encrypt to all recipients
        src = data_path(MSG_TXT)
        dst, dec = reg_workfiles('weird_userids_special_2', '.rnp', '.dec')
        rnp_encrypt_file_ex(src, dst, list(map(lambda uid: uid, USERIDS)), None, None) 
        # Decrypt file with each of the passwords
        for pswd in KEYPASS:
            multiple_pass_attempts = (pswd + '\n') * len(KEYPASS)
            rnp_decrypt_file(dst, dec, multiple_pass_attempts)
            compare_files(src, dec, RNP_DATA_DIFFERS)
            remove_files(dec)
        # Cleanup
        clear_workfiles()

    def test_encryption_weird_userids_unicode(self):
        USERIDS_1 = [
            WEIRD_USERID_UNICODE_1, WEIRD_USERID_UNICODE_2]
        USERIDS_2 = [
            WEIRD_USERID_UNICODE_1, WEIRD_USERID_UNICODE_2]
        # The idea is to generate keys with USERIDS_1 and encrypt with USERIDS_2
        # (that differ only in case)
        # But currently Unicode case-insensitive search is not working,
        # so we're encrypting with exactly the same recipient
        KEYPASS = ['encUnicodePass1', 'encUnicodePass2']
        # Generate multiple keys
        for uid, pswd in zip(USERIDS_1, KEYPASS):
            rnp_genkey_rsa(uid, 1024, pswd)
        # Encrypt to all recipients
        src = data_path('test_messages') + '/message.txt'
        dst, dec = reg_workfiles('weird_unicode', '.rnp', '.dec')
        rnp_encrypt_file_ex(src, dst, list(map(lambda uid: uid, USERIDS_2)), None, None) 
        # Decrypt file with each of the passwords
        for pswd in KEYPASS:
            multiple_pass_attempts = (pswd + '\n') * len(KEYPASS)
            rnp_decrypt_file(dst, dec, multiple_pass_attempts)
            compare_files(src, dec, RNP_DATA_DIFFERS)
            remove_files(dec)
        # Cleanup
        clear_workfiles()

    def test_encryption_x25519(self):
        # Make sure that we support import and decryption using both tweaked and non-tweaked keys
        KEY_IMPORT = r'(?s)^.*' \
        r'sec.*255/EdDSA.*3176fc1486aa2528.*' \
        r'uid.*eddsa-25519-non-tweaked.*' \
        r'ssb.*255/ECDH.*950ee0cd34613dba.*$'
        BITS_MSG = r'(?s)^.*Warning: bits of 25519 secret key are not tweaked.*$'

        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--import', data_path(KEY_25519_NOTWEAK_SEC)])
        self.assertEqual(ret, 0)
        self.assertRegex(out, KEY_IMPORT)
        ret, _, err = run_proc(RNP, ['--homedir', RNPDIR, '-d', data_path(MSG_ES_25519)])
        self.assertEqual(ret, 0)
        self.assertRegex(err, BITS_MSG)
        self.assertRegex(err, r'(?s)^.*Signature\(s\) verified successfully.*$')
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--remove-key', 'eddsa-25519-non-tweaked', '--force'])
        self.assertEqual(ret, 0)
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--import', data_path('test_key_edge_cases/key-25519-tweaked-sec.asc')])
        self.assertEqual(ret, 0)
        self.assertRegex(out, KEY_IMPORT)
        ret, _, err = run_proc(RNP, ['--homedir', RNPDIR, '-d', data_path(MSG_ES_25519)])
        self.assertEqual(ret, 0)
        self.assertNotRegex(err, BITS_MSG)
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--remove-key', 'eddsa-25519-non-tweaked', '--force'])
        self.assertEqual(ret, 0)
        # Due to issue in GnuPG it reports successfull import of non-tweaked secret key in batch mode
        ret, _, _ = run_proc(GPG, ['--batch', '--homedir', GPGHOME, '--import', data_path(KEY_25519_NOTWEAK_SEC)])
        self.assertEqual(ret, 0)
        ret, _, _ = run_proc(GPG, ['--batch', '--homedir', GPGHOME, '-d', data_path(MSG_ES_25519)])
        self.assertNotEqual(ret, 0)
        ret, _, _ = run_proc(GPG, ['--batch', '--homedir', GPGHOME, '--yes', '--delete-secret-key', 'dde0ee539c017d2bd3f604a53176fc1486aa2528'])
        self.assertEqual(ret, 0)
        # Make sure GPG imports tweaked key and successfully decrypts message
        ret, _, _ = run_proc(GPG, ['--batch', '--homedir', GPGHOME, '--import', data_path('test_key_edge_cases/key-25519-tweaked-sec.asc')])
        self.assertEqual(ret, 0)
        ret, _, _ = run_proc(GPG, ['--batch', '--homedir', GPGHOME, '-d', data_path(MSG_ES_25519)])
        self.assertEqual(ret, 0)
        # Generate
        pipe = pswd_pipe(PASSWORD)
        ret, _, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--pass-fd', str(pipe), '--userid',
                                      'eddsa_25519', '--generate-key', '--expert'], '22\n')
        os.close(pipe)
        self.assertEqual(ret, 0)
        # Export
        ret, out, _ = run_proc(RNPK, ['--homedir', RNPDIR, '--export', '--secret', 'eddsa_25519'])
        self.assertEqual(ret, 0)
        # Import key with GPG
        ret, out, _ = run_proc(GPG, ['--batch', '--homedir', GPGHOME, '--import'], out)
        self.assertEqual(ret, 0)
        src, dst, dec = reg_workfiles('cleartext', '.txt', '.rnp', '.dec')
        # Generate random file of required size
        random_text(src, 1000)
        # Encrypt and sign with RNP
        ret, out, _ = run_proc(RNP, ['--homedir', RNPDIR, '-es', '-r', 'eddsa_25519', '-u', 
                                     'eddsa_25519', '--password', PASSWORD, src, '--output', dst, '--armor'])
        # Decrypt and verify with RNP
        rnp_decrypt_file(dst, dec, 'password')
        self.assertEqual(file_text(src), file_text(dec))
        remove_files(dec)
        # Decrypt and verify with GPG
        gpg_decrypt_file(dst, dec, 'password')
        self.assertEqual(file_text(src), file_text(dec))
        remove_files(dst, dec)
        # Encrypt and sign with GnuPG
        ret, _, _ = run_proc(GPG, ['--batch', '--homedir', GPGHOME, '--always-trust', '-r', 'eddsa_25519',
                             '-u', 'eddsa_25519', '--output', dst, '-es', src])
        self.assertEqual(ret, 0)
        # Decrypt and verify with RNP
        rnp_decrypt_file(dst, dec, 'password')
        self.assertEqual(file_text(src), file_text(dec))
        # Cleanup
        clear_workfiles()

class Compression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Compression is currently implemented only for encrypted messages
        rnp_genkey_rsa(KEY_ENCRYPT)
        rnp_genkey_rsa(KEY_SIGN_GPG)
        gpg_import_pubring()
        gpg_import_secring()

    @classmethod
    def tearDownClass(cls):
        clear_keyrings()

    def tearDown(self):
        clear_workfiles()

    def test_rnp_compression(self):
        runs = 30
        levels = list_upto([None, 0, 2, 4, 6, 9], runs)
        algosrnp = list_upto([None, 'zip', 'zlib', 'bzip2'], runs)
        sizes = list_upto([20, 1000, 5000, 15000, 250000], runs)

        for level, algo, size in zip(levels, algosrnp, sizes):
            z = [algo, level]
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
            rnp_detached_signing_gpg_to_rnp(size, True)
            rnp_cleartext_signing_gpg_to_rnp(size)

    def test_rnp_multiple_signers(self):
        USERIDS = ['sign1@rnp', 'sign2@rnp', 'sign3@rnp']
        KEYPASS = ['sign1pass', 'sign2pass', 'sign3pass']

        # Generate multiple keys and import to GnuPG
        for uid, pswd in zip(USERIDS, KEYPASS):
            rnp_genkey_rsa(uid, 1024, pswd)

        gpg_import_pubring()
        gpg_import_secring()

        src, dst, sig, ver = reg_workfiles('cleartext', '.txt', '.rnp', EXT_SIG, '.ver')
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

    def test_sign_weird_userids(self):
        USERIDS = [WEIRD_USERID_SPECIAL_CHARS, WEIRD_USERID_SPACE, WEIRD_USERID_QUOTE,
            WEIRD_USERID_SPACE_AND_QUOTE, WEIRD_USERID_QUOTE_AND_SPACE,
            WEIRD_USERID_UNICODE_1, WEIRD_USERID_UNICODE_2]
        KEYPASS = ['signUnicodePass1', 'signUnicodePass2', 'signUnicodePass3', 'signUnicodePass4',
            'signUnicodePass5', 'signUnicodePass6', 'signUnicodePass7']

        # Generate multiple keys
        for uid, pswd in zip(USERIDS, KEYPASS):
            rnp_genkey_rsa(uid, 1024, pswd)

        gpg_import_pubring()
        gpg_import_secring()

        src, dst, sig, ver = reg_workfiles('cleartext', '.txt', '.rnp', EXT_SIG, '.ver')
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
    def _encrypt_decrypt(self, e1, e2, failenc = False, faildec = False):
        keyfile, src, enc_out, dec_out = reg_workfiles(self.test_id, '.gpg',
                                                         '.in', '.enc', '.dec')
        random_text(src, 0x1337)

        if not self.operation_key_location and not self.operation_key_gencmd:
            raise RuntimeError("key not found")

        if self.operation_key_location:
            self.assertTrue(e1.import_key(self.operation_key_location[0]))
            self.assertTrue(e1.import_key(self.operation_key_location[1], True))
        else:
            self.assertTrue(e1.generate_key_batch(self.operation_key_gencmd))

        self.assertTrue(e1.export_key(keyfile, False))
        self.assertTrue(e2.import_key(keyfile))
        self.assertEqual(e2.encrypt(e1.userid, enc_out, src), not failenc)
        self.assertEqual(e1.decrypt(dec_out, enc_out), not faildec)
        clear_workfiles()

    def setUp(self):
        self.rnp = Rnp(RNPDIR, RNP, RNPK)
        self.gpg = GnuPG(GPGHOME, GPG)
        self.rnp.password = self.gpg.password = PASSWORD
        self.rnp.userid = self.gpg.userid = self.test_id + AT_EXAMPLE

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
        Preferences: aes256 sha256 sha384 sha512 sha1 zlib
        Name-Email: {2}
        """

    RNP_GENERATE_DSA_ELGAMAL_PATTERN = "16\n{0}\n"

    @staticmethod
    def key_pfx(sign_key_size, enc_key_size):
        return "GnuPG_dsa_elgamal_%d_%d" % (sign_key_size, enc_key_size)

    def do_test_encrypt(self, sign_key_size, enc_key_size):
        pfx = EncryptElgamal.key_pfx(sign_key_size, enc_key_size)
        self.operation_key_location = tuple((key_path(pfx, False), key_path(pfx, True)))
        self.rnp.userid = self.gpg.userid = pfx + AT_EXAMPLE
        # DSA 1024 key uses SHA-1 as hash so verification would fail
        self._encrypt_decrypt(self.gpg, self.rnp, sign_key_size <= 1024, sign_key_size <= 1024)

    def do_test_decrypt(self, sign_key_size, enc_key_size):
        pfx = EncryptElgamal.key_pfx(sign_key_size, enc_key_size)
        self.operation_key_location = tuple((key_path(pfx, False), key_path(pfx, True)))
        self.rnp.userid = self.gpg.userid = pfx + AT_EXAMPLE
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
        # Will fail since 1024-bit DSA key uses SHA-1 as hash.
        self._encrypt_decrypt(self.gpg, self.rnp, True, True)

    def test_generate_elgamal_key1536_in_gpg_and_encrypt(self):
        cmd = EncryptElgamal.GPG_GENERATE_DSA_ELGAMAL_PATTERN.format(1536, 1536, self.gpg.userid)
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
        Preferences: aes256 sha256 sha384 sha512 sha1 zlib
        Name-Email: {1}"""

    RNP_GENERATE_ECDH_ECDSA_PATTERN = "19\n{0}\n"

    def test_encrypt_nistP256(self):
        self.operation_key_gencmd = EncryptEcdh.GPG_GENERATE_ECDH_ECDSA_PATTERN.format(
            "nistp256", self.rnp.userid)
        self._encrypt_decrypt(self.gpg, self.rnp)

    def test_encrypt_nistP384(self):
        self.operation_key_gencmd = EncryptEcdh.GPG_GENERATE_ECDH_ECDSA_PATTERN.format(
            "nistp384", self.rnp.userid)
        self._encrypt_decrypt(self.gpg, self.rnp)

    def test_encrypt_nistP521(self):
        self.operation_key_gencmd = EncryptEcdh.GPG_GENERATE_ECDH_ECDSA_PATTERN.format(
            "nistp521", self.rnp.userid)
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

    def _sign_verify(self, e1, e2, failsign = False, failver = False):
        '''
        Helper function for Sign verification
        1. e1 creates/loads key
        2. e1 exports key
        3. e2 imports key
        2. e1 signs message
        3. e2 verifies message

        eX == entityX
        '''
        keyfile, src, output = reg_workfiles(self.test_id, '.gpg', '.in', '.out')
        random_text(src, 0x1337)

        if not self.operation_key_location and not self.operation_key_gencmd:
            print(self.operation_key_gencmd)
            raise RuntimeError("key not found")

        if self.operation_key_location:
            self.assertTrue(e1.import_key(self.operation_key_location[0]))
            self.assertTrue(e1.import_key(self.operation_key_location[1], True))
        else:
            self.assertTrue(e1.generate_key_batch(self.operation_key_gencmd))
        self.assertTrue(e1.export_key(keyfile, False))
        self.assertTrue(e2.import_key(keyfile))
        self.assertEqual(e1.sign(output, src), not failsign)
        self.assertEqual(e2.verify(output), not failver)
        clear_workfiles()

    def setUp(self):
        self.rnp = Rnp(RNPDIR, RNP, RNPK)
        self.gpg = GnuPG(GPGHOME, GPG)
        self.rnp.password = self.gpg.password = PASSWORD
        self.rnp.userid = self.gpg.userid = self.test_id + AT_EXAMPLE

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
    def key_pfx(p): return "GnuPG_dsa_elgamal_%d_%d" % (p, p)

    def do_test_sign(self, p_size):
        pfx = SignDSA.key_pfx(p_size)
        self.operation_key_location = tuple((key_path(pfx, False), key_path(pfx, True)))
        self.rnp.userid = self.gpg.userid = pfx + AT_EXAMPLE
        # DSA 1024-bit key uses SHA-1 so verification would fail
        self._sign_verify(self.rnp, self.gpg, p_size <= 1024, p_size <= 1024)

    def do_test_verify(self, p_size):
        pfx = SignDSA.key_pfx(p_size)
        self.operation_key_location = tuple((key_path(pfx, False), key_path(pfx, True)))
        self.rnp.userid = self.gpg.userid = pfx + AT_EXAMPLE
        # DSA 1024-bit key uses SHA-1 so verification would fail
        self._sign_verify(self.gpg, self.rnp, False, p_size <= 1024)

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
    def key_pfx(p): return "GnuPG_rsa_%d_%d" % (p, p)

    def do_encrypt_verify(self, key_size):
        pfx = EncryptSignRSA.key_pfx(key_size)
        self.operation_key_location = tuple((key_path(pfx, False), key_path(pfx, True)))
        self.rnp.userid = self.gpg.userid = pfx + AT_EXAMPLE
        self._encrypt_decrypt(self.gpg, self.rnp)
        self._sign_verify(self.gpg, self.rnp)

    def do_rnp_decrypt_sign(self, key_size):
        pfx = EncryptSignRSA.key_pfx(key_size)
        self.operation_key_location = tuple((key_path(pfx, False), key_path(pfx, True)))
        self.rnp.userid = self.gpg.userid = pfx + AT_EXAMPLE
        self._encrypt_decrypt(self.rnp, self.gpg)
        self._sign_verify(self.rnp, self.gpg)

    def test_rnp_encrypt_verify_1024(self): self.do_encrypt_verify(1024)
    def test_rnp_encrypt_verify_2048(self): self.do_encrypt_verify(2048)
    def test_rnp_encrypt_verify_4096(self): self.do_encrypt_verify(4096)

    def test_rnp_decrypt_sign_1024(self): self.do_rnp_decrypt_sign(1024)
    def test_rnp_decrypt_sign_2048(self): self.do_rnp_decrypt_sign(2048)
    def test_rnp_decrypt_sign_4096(self): self.do_rnp_decrypt_sign(4096)

    def setUp(self):
        Encrypt.setUp(self)

    @classmethod
    def tearDownClass(cls):
        Encrypt.tearDownClass()

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
    if not hasattr(main, 'USAGE'):
        main.USAGE = ''
    main.USAGE += ''.join([
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
        except Exception:
            pass
