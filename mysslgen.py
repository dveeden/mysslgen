#!/usr/bin/python3 -tt
import base64
import os
import io
import logging
import argparse
try:
    import configparser
except ImportError:
    import ConfigParser as configparser
import platform
import stat

# External
from OpenSSL import crypto

logging.basicConfig(logging=logging.DEBUG)
mylog = logging.getLogger(__name__)
mylog.setLevel(logging.DEBUG)

parser = argparse.ArgumentParser(description='Manage SSL Certificates for MySQL')
parser.add_argument('--config', dest='conffile', default='/etc/my.cnf')
parser.add_argument('--ssldir', dest='ssldir', default='/etc/mysql/ssl')
args = parser.parse_args()

daysvalid = 365
ssldir = args.ssldir
CAkeyfile = os.path.join(ssldir, 'CAkey.pem')
CAcertfile = os.path.join(ssldir, 'CAcert.pem')
serverkeyfile = os.path.join(ssldir, 'server-key.pem')
servercertfile = os.path.join(ssldir, 'server-cert.pem')
clientkeyfile = os.path.join(ssldir, 'client-key.pem')
clientcertfile = os.path.join(ssldir, 'client-cert.pem')

if os.path.exists(args.conffile):
    conffile = args.conffile
elif os.path.exists('/etc/mysql/my.cnf'):
    conffile = '/etc/mysql/my.cnf'
    mylog.warning('Specified Config file {pconffile} does not exist, using {conffile} instead.'.format(pconffile=args.conffile, conffile=conffile))
else:
    raise FileNotFoundError('Config file {pconffile} was not found'.format(pconffile=args.conffile))

myconfig = configparser.ConfigParser(allow_no_value=True)
myconfig.read(conffile)

if not os.path.isdir(ssldir):
    mylog.info('SSL Directory {ssldir} does not exist, creating it.'.format(ssldir=ssldir))
    os.mkdir(ssldir, mode=0o700)

if os.path.isdir(ssldir):
    ssldirSecure = stat.S_IMODE(os.lstat(ssldir).st_mode) == 0o700
    if not ssldirSecure:
        mylog.info('SSL Directory {ssldir} is not secure.'.format(ssldir=ssldir))

if not os.path.exists(CAkeyfile) or os.stat(CAkeyfile).st_size == 0:
    mylog.info('No or empty CA key file found, creating it.')
    CAkey = crypto.PKey()
    CAkey.generate_key(crypto.TYPE_RSA, 2048)
    oldumask = os.umask(0o077)
    with open(CAkeyfile, 'w') as fh:
        pemkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, CAkey)
        fh.write(pemkey.decode('ascii'))
    os.umask(oldumask)
else:
    mylog.info('Loading CA key.')
    with open(CAkeyfile, 'r') as fh:
        pemkey = fh.read()
    CAkey = crypto.load_privatekey(crypto.FILETYPE_PEM, pemkey)
    CAkeyfileSecure = stat.S_IMODE(os.lstat(CAkeyfile).st_mode) == 0o600
    if not CAkeyfileSecure:
        mylog.info('CA key {CAkeyfile} is not secure.'.format(CAkeyfile=CAkeyfile))

if not os.path.exists(CAcertfile) or os.stat(CAcertfile).st_size == 0:
    mylog.info('No or empty CA certificate file found, creating it.')
    CAcert = crypto.X509()
    CAcert.get_subject().CN = 'MySQL CA {node}'.format(node=platform.node())
    CAcert.gmtime_adj_notBefore(0)
    CAcert.gmtime_adj_notAfter(60*60*24*daysvalid)
    CAcert.set_serial_number(0x1)
    CAcert.set_pubkey(CAkey)
    CAcert.set_issuer(CAcert.get_subject())
    CAcert.add_extensions([
        crypto.X509Extension(b"basicConstraints", False, b"CA:TRUE"),
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=CAcert)
    ])
    CAcert.add_extensions([
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=CAcert)
    ])
    CAcert.add_extensions([
        crypto.X509Extension(b"crlDistributionPoints", False, b"URI:http://127.0.0.1/my.crl", issuer=CAcert)
    ])
    CAcert.sign(CAkey, 'sha1')
    with open(CAcertfile, 'w') as fh:
        pemcert = crypto.dump_certificate(crypto.FILETYPE_PEM, CAcert)
        fh.write(pemcert.decode('ascii'))
else:
    mylog.info('Loading CA certificate.')
    with open(CAcertfile, 'r') as fh:
        pemcert = fh.read()
    CAcert = crypto.load_certificate(crypto.FILETYPE_PEM, pemcert)

if not os.path.exists(serverkeyfile) or os.stat(serverkeyfile).st_size == 0:
    mylog.info('No or empty server key file found, creating it.')
    serverkey = crypto.PKey()
    serverkey.generate_key(crypto.TYPE_RSA, 2048)
    oldumask = os.umask(0o077)
    with open(serverkeyfile, 'w') as fh:
        # The FILETYPE_PEM generates a PKCS#8 which doesn't work
        # for MySQL (Bug #71271)
        # pemkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, serverkey)
        asn1key = crypto.dump_privatekey(crypto.FILETYPE_ASN1, serverkey)
        b64key = base64.b64encode(asn1key)
        fh.write('-----BEGIN RSA PRIVATE KEY-----\n')
        b64str = b64key.decode('ascii')
        start = 0
        while len(b64str) > start+64:
            fh.write(b64str[start:start+64] + '\n')
            start += 64
        else:
            fh.write(b64str[start:start+64] + '\n')
        fh.write('-----END RSA PRIVATE KEY-----\n')
    os.umask(oldumask)
else:
    mylog.info('Loading server key.')
    with open(serverkeyfile, 'r') as fh:
        pemkey = fh.read()
    serverkey = crypto.load_privatekey(crypto.FILETYPE_PEM, pemkey)
    serverkeySecure = stat.S_IMODE(os.lstat(CAkeyfile).st_mode) == 0o600
    if not serverkeySecure:
        mylog.info('Server key {serverkeyfile} is not secure.'.format(serverkeyfile=serverkeyfile))

if not os.path.exists(servercertfile) or os.stat(servercertfile).st_size == 0:
    mylog.info('No or empty server certificate file found, creating it.')
    servercert = crypto.X509()
    servercert.get_subject().CN = 'MySQL Server {node}'.format(node=platform.node())
    servercert.gmtime_adj_notBefore(0)
    servercert.gmtime_adj_notAfter(60*60*24*daysvalid)
    servercert.set_serial_number(0x2)
    servercert.set_pubkey(serverkey)
    servercert.set_issuer(CAcert.get_subject())
    servercert.add_extensions([
        crypto.X509Extension(b"crlDistributionPoints", False, b"URI:http://127.0.0.1/my.crl", issuer=CAcert)
    ])
    servercert.sign(CAkey, 'sha1')
    with open(servercertfile, 'w') as fh:
        pemcert = crypto.dump_certificate(crypto.FILETYPE_PEM, servercert)
        fh.write(pemcert.decode('ascii'))
else:
    mylog.info('Loading server certificate.')
    with open(servercertfile, 'r') as fh:
        pemcert = fh.read()
    servercert = crypto.load_certificate(crypto.FILETYPE_PEM, pemcert)

sslconf = {}
configadd = configparser.ConfigParser()
configadd.add_section('mysqld')
try:
    sslconf['ca'] = myconfig.get('mysqld', 'ssl-ca')
except configparser.NoOptionError as msg:
    configadd.set('mysqld', 'ssl-ca', CAcertfile)

try:
    sslconf['cert'] = myconfig.get('mysqld', 'ssl-cert')
except configparser.NoOptionError as msg:
    configadd.set('mysqld', 'ssl-cert', servercertfile)

try:
    sslconf['key'] = myconfig.get('mysqld', 'ssl-key')
except configparser.NoOptionError as msg:
    configadd.set('mysqld', 'ssl-key', serverkeyfile)

if 'ca' in sslconf and sslconf['ca'] != CAcertfile:
    mylog.warning('Wrong ssl-ca in config: {confca} instead of {realca}.'.format(confca=sslconf['ca'], realca=CAcertfile))
    configadd.set('mysqld', 'ssl-ca', CAcertfile)
if 'cert' in sslconf and sslconf['cert'] != servercertfile:
    mylog.warning('Wrong ssl-cert in config: {confcert} instead of {realcert}.'.format(confcert=sslconf['cert'], realcert=servercertfile))
    configadd.set('mysqld', 'ssl-cert', servercertfile)
if 'key' in sslconf and sslconf['key'] != serverkeyfile:
    mylog.warning('Wrong ssl-key in config: {confkey} instead of {realkey}.'.format(confkey=sslconf['key'], realkey=serverkeyfile))
    configadd.set('mysqld', 'ssl-key', serverkeyfile)

optcount = len(configadd.options('mysqld'))
mylog.debug('Optcount: {optcount}'.format(optcount=optcount))
if optcount > 0:
    print('Please add/change these settings in {conffile}:'.format(conffile=conffile))
    print('-------------------------')
    addconf = io.StringIO()
    configadd.write(addconf)
    addconf.seek(0)
    print(addconf.read())
    print('-------------------------')
    print('After setting these you need to restart MySQL to activate these settings')
else:
    mylog.info('SSL options are present in {conffile}.'.format(conffile=conffile))

if not os.path.exists(clientkeyfile) or os.stat(clientkeyfile).st_size == 0:
    mylog.info('No or empty client key file found, creating it.')
    clientkey = crypto.PKey()
    clientkey.generate_key(crypto.TYPE_RSA, 2048)
    oldumask = os.umask(0o077)
    with open(clientkeyfile, 'w') as fh:
        # The FILETYPE_PEM generates a PKCS#8 which doesn't work
        # for MySQL (Bug #71271)
        # pemkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, clientkey)
        asn1key = crypto.dump_privatekey(crypto.FILETYPE_ASN1, clientkey)
        b64key = base64.b64encode(asn1key)
        fh.write('-----BEGIN RSA PRIVATE KEY-----\n')
        b64str = b64key.decode('ascii')
        start = 0
        while len(b64str) > start+64:
            fh.write(b64str[start:start+64] + '\n')
            start += 64
        else:
            fh.write(b64str[start:start+64] + '\n')
        fh.write('-----END RSA PRIVATE KEY-----\n')
    os.umask(oldumask)
else:
    mylog.info('Loading client key.')
    with open(clientkeyfile, 'r') as fh:
        pemkey = fh.read()
    clientkey = crypto.load_privatekey(crypto.FILETYPE_PEM, pemkey)
    # TODO: Check if the permissions on the key file are secure

if not os.path.exists(clientcertfile) or os.stat(clientcertfile).st_size == 0:
    mylog.info('No or empty client certificate file found, creating it.')
    clientcert = crypto.X509()
    clientcert.get_subject().CN = 'MySQL Server {node}'.format(node=platform.node())
    clientcert.gmtime_adj_notBefore(0)
    clientcert.gmtime_adj_notAfter(60*60*24*daysvalid)
    clientcert.set_serial_number(0x3)
    clientcert.set_pubkey(clientkey)
    clientcert.set_issuer(CAcert.get_subject())
    clientcert.add_extensions([
        crypto.X509Extension(b"crlDistributionPoints", False, b"URI:http://127.0.0.1/my.crl", issuer=CAcert)
    ])
    clientcert.sign(CAkey, 'sha1')
    with open(clientcertfile, 'w') as fh:
        pemcert = crypto.dump_certificate(crypto.FILETYPE_PEM, clientcert)
        fh.write(pemcert.decode('ascii'))
else:
    mylog.info('Loading client certificate.')
    with open(clientcertfile, 'r') as fh:
        pemcert = fh.read()
    clientcert = crypto.load_certificate(crypto.FILETYPE_PEM, pemcert)

print('The client setup: (Place in ~/.my.cnf or your global config)')
print('[client]')
print('ssl-ca = {cafile}'.format(cafile=CAcertfile))
print('ssl-cert = {certfile}'.format(certfile=clientcertfile))
print('ssl-key = {keyfile}'.format(keyfile=clientkeyfile))
print('\nDon\'t forget to specify REQUIRE SSL or REQUIRE X509 (if you want to force SSL for a user.')
print('See also: http://dev.mysql.com/doc/refman/5.7/en/grant.html')
