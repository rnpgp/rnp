# redumper: rnp based PGP packet dumper

## Overview

**redumper** parses input formated as OpenPGP packets ([RFC4880-bis-02](https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-02)) and prints it out in human readable form. **redumper** is based on [rnp](https://github.com/riboseinc/rnp) library (by [Ribose Inc](https://www.ribose.com)).

## Usage

```           
    redumper -i input.pgp [-d] [-h]
        -i input_file [mandatory]: input file
        -d : indicates whether to print packet content. Data is represented as hex
        -h : prints help and exists
```

## Example

In order to visualise OpenPGP formated data, simply call ``redumper`` with ``-i`` option:

```
    ./redumper -i input.pgp
```

Example output:

```
* PACKET: Secret Key (tag 5) (958 bytes) offset=0x0 format=new
       S2K Usage: 254
       S2K Specifier: 3
       Symmetric algorithm: CAST5 (0x3)
       Hash algorithm: SHA256 (0x8)
       Salt: [data size: 8 bytes]
       Octet count: 65536
       IV: [data size: 8 bytes]

* PACKET: User ID (tag 13) (54 bytes) offset=0x3c1 format=new
       userid: RSA (Encrypt or Sign) 2048-bit key <flowher@localhost>

* PACKET: Signature (tag 2) (306 bytes) offset=0x3f9 format=new
       Version: 4
       Signature Type: Positive certification of a User ID and Public Key packet (0x13)
       Public Key Algorithm: RSA (Encrypt or Sign) (0x1)
       Hash Algorithm: SHA256 (0x8)
       Hashed data len: 0
       * Signature Creation Time (type 0x02)
               Signature Creation Time: time=1504459919 (Sun Sep  3 18:31:59 2017)
       * Key Flags (type 0x1b)
               Key Flags: [data size: 1 bytes]
               .. May be used to sign data
               .. May be used to certify other keys
       * Preferred Symmetric Algorithms (type 0x0b)
               Preferred Symmetric Algorithms: [data size: 4 bytes]
               .. AES (256-bit key)
               .. AES (192-bit key)
               .. AES (128-bit key)
               .. TripleDES
       * Preferred Hash Algorithms (type 0x15)
               Preferred Hash Algorithms: [data size: 5 bytes]
               .. SHA256
               .. SHA384
               .. SHA512
               .. SHA224
               .. SHA1
       * Preferred Compression Algorithms (type 0x16)
               Preferred Compression Algorithms: [data size: 4 bytes]
               .. ZLIB(RFC1950)
               .. Bzip2(BZ2)
               .. ZIP(RFC1951)
               .. Uncompressed
       * Issuer key ID (type 0x10)
               Issuer Key Id: [data size: 8 bytes]
               hash2: [data size: 2 bytes]
       RSA sign = 0CE2134C4AAD4384395CD361A6A259420CE2134C4AAD4384395CD361A6A25942 (256 bits)

* PACKET: Symmetric Encrypted and Integrity Protected Data (tag 18) (6177 bytes) offset=0x10f format=new
[data size: 6176 bytes]
```

Each OpenPGP packet that's found in the input, starts with ``* PACKET ...`` line. The line contains following informations:
* Packet type (Signature, Secret Key, etc.)
* ID of a tag corresponding to the packet type as defined in RFC
* Size of whole packet
* Location of the packet in the input file as an offset from beginning of the file
* Format of the packet length - either 'old' or 'new' (see 4.2.1 and 4.2.2 of RFC 4880 for definition of "old" and "new") 
* Packet length type (only if packet format length is "old")

**redumper** won't perform any cryptographic operation on data (like decryption or signature validation). By default 
it will only display size of the packet content. Nevertheless it is possible to dump packet content by providing ``-d`` flag.

```
> ./redumper -i encrypted.gpg -d

* PACKET: Public-Key Encrypted Session Key (tag 1) (268 bytes) offset=0x0 format=new
       Version: 3
       Key ID:         (8 bytess):
00000 | c4 27 10 dc 85 4a 89 ac                          | .'...J..        
       Algorithm: RSA (Encrypt or Sign) (0x1)
       encrypted_m = 1A62422473417791C0B92BAB491262B1655C31530B6714760B6E9502C4B470562F3174EFF2FA4EAF0E800B1B9E64C476B6EC747B1D903D624174B803CBA4B17A19EBEF9A4E7B0F96BA2DE953F6BB8C0FA91A71BEF1497C4439EB4FED8A71FC0DB86EC83540871BA21D7C2E4765C1AC3865701DF8A8CA1B3779189015C58357E8F6ECE9B51ECC1BAEC8616D36F1C5CA57CB3F9FB6A6116883D6BC0974A454AB08F1892D48F4E4BC07DE8E2080D19C17BA19283BCF6FD711D4909977EC00DC1FBB2BB351CF24EB728F9AA5ED5D191D31A13D32BCC5B1DD227D30CA75C24448395EEF73BA98404B1825F42C572F4386E31BABCC4582861D2532BCE6D8F6C35B07A3 (2045 bits)
       Version: 3
       Key ID:         (8 bytess):
00000 | c4 27 10 dc 85 4a 89 ac                          | .'...J..        
       Algorithm: RSA (Encrypt or Sign) (0x1)
       encrypted_m = 1A62422473417791C0B92BAB491262B1655C31530B6714760B6E9502C4B470562F3174EFF2FA4EAF0E800B1B9E64C476B6EC747B1D903D624174B803CBA4B17A19EBEF9A4E7B0F96BA2DE953F6BB8C0FA91A71BEF1497C4439EB4FED8A71FC0DB86EC83540871BA21D7C2E4765C1AC3865701DF8A8CA1B3779189015C58357E8F6ECE9B51ECC1BAEC8616D36F1C5CA57CB3F9FB6A6116883D6BC0974A454AB08F1892D48F4E4BC07DE8E2080D19C17BA19283BCF6FD711D4909977EC00DC1FBB2BB351CF24EB728F9AA5ED5D191D31A13D32BCC5B1DD227D30CA75C24448395EEF73BA98404B1825F42C572F4386E31BABCC4582861D2532BCE6D8F6C35B07A3 (2045 bits)
       Packet contents (271 bytess):
00000 | c1 c0 4c 03 c4 27 10 dc 85 4a 89 ac 01 07 fd 1a  | ..L..'...J......
00016 | 62 42 24 73 41 77 91 c0 b9 2b ab 49 12 62 b1 65  | bB$sAw...+.I.b.e
00032 | 5c 31 53 0b 67 14 76 0b 6e 95 02 c4 b4 70 56 2f  | \1S.g.v.n....pV/
00048 | 31 74 ef f2 fa 4e af 0e 80 0b 1b 9e 64 c4 76 b6  | 1t...N......d.v.
00064 | ec 74 7b 1d 90 3d 62 41 74 b8 03 cb a4 b1 7a 19  | .t{..=bAt.....z.
00080 | eb ef 9a 4e 7b 0f 96 ba 2d e9 53 f6 bb 8c 0f a9  | ...N{...-.S.....
00096 | 1a 71 be f1 49 7c 44 39 eb 4f ed 8a 71 fc 0d b8  | .q..I|D9.O..q...
00112 | 6e c8 35 40 87 1b a2 1d 7c 2e 47 65 c1 ac 38 65  | n.5@....|.Ge..8e
00128 | 70 1d f8 a8 ca 1b 37 79 18 90 15 c5 83 57 e8 f6  | p.....7y.....W..
00144 | ec e9 b5 1e cc 1b ae c8 61 6d 36 f1 c5 ca 57 cb  | ........am6...W.
00160 | 3f 9f b6 a6 11 68 83 d6 bc 09 74 a4 54 ab 08 f1  | ?....h....t.T...
00176 | 89 2d 48 f4 e4 bc 07 de 8e 20 80 d1 9c 17 ba 19  | .-H...... ......
00192 | 28 3b cf 6f d7 11 d4 90 99 77 ec 00 dc 1f bb 2b  | (;.o.....w.....+
00208 | b3 51 cf 24 eb 72 8f 9a a5 ed 5d 19 1d 31 a1 3d  | .Q.$.r....]..1.=
00224 | 32 bc c5 b1 dd 22 7d 30 ca 75 c2 44 48 39 5e ef  | 2...."}0.u.DH9^.
00240 | 73 ba 98 40 4b 18 25 f4 2c 57 2f 43 86 e3 1b ab  | s..@K.%.,W/C....
00256 | cc 45 82 86 1d 25 32 bc e6 d8 f6 c3 5b 07 a3     | .E...%2.....[.. 

* PACKET: Symmetric Encrypted and Integrity Protected Data (tag 18) (6177 bytes) offset=0x10f format=new
       data (6176 bytess):
00000 | 89 36 f8 82 b3 9a 87 49 57 eb 58 cd 41 ef db ba  | .6.....IW.X.A...
00016 | cd ac 55 48 44 7c 88 4c 32 7c d7 24 17 53 f3 a7  | ..UHD|.L2|.$.S..
00032 | 5d 42 36 46 69 a2 79 57 1a 4d e3 ef 38 3f 80 a1  | ]B6Fi.yW.M..8?..
00048 | a6 19 8a ca 88 6f e4 42 79 45 42 dc f8 8f c6 95  | .....o.ByEB.....
00064 | 84 0d a7 2f 7f ce 03 e3 d6 eb c6 2d d9 8a 58 48  | .../.......-..XH
00080 | c3 54 8a 99 ae cd 76 7c 7c 02 8b 5b eb e0 d5 86  | .T....v||..[....
00096 | f3 ec 70 34 d9 23 84 5c ac 16 f6 56 42 6a 9c 8b  | ..p4.#.\...VBj..
00112 | 12 cc ef 15 d1 03 2f 33 39 5e 48 bc e3 12 10 36  | ....../39^H....6
00128 | ec ca ae d5 72 c0 81 13 03 3b 49 e5 32 af e6 6c  | ....r....;I.2..l
00144 | 9b 1c 91 41 73 9f ff df 52 74 af 75 0c 00 41 c6  | ...As...Rt.u..A.
00160 | d2 a6 66 6a 8c 26 61 73 0b c4 f2 63 0f 3d b7 68  | ..fj.&as...c.=.h
00176 | 3b 24 9d 30 fa 49 e1 52 2a b4 aa c1 d2 42 cf 93  | ;$.0.I.R*....B..
00192 | ae 08 59 8f ba bf 34 07 4c eb 14 95 a1 64 94 cf  | ..Y...4.L....d..
....
```
