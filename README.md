
Description
===========

This is a tool to help and configure MySQL for use with SSL

It will create a certificate authoritity in /etc/mysql/ssl and 
generate a keypair for the server and a keypair for the client.

It will generate the server and client options which must be 
added to your configuation.

Usage
=====
usage: mysslgen.py [-h] [--config CONFFILE] [--ssldir SSLDIR]

Manage SSL Certificates for MySQL

optional arguments:
  -h, --help         show this help message and exit
  --config CONFFILE
  --ssldir SSLDIR

You'll need to do a "chown -R mysql:mysql /etc/mysql/ssl" to 
make sure MySQL is able to read the key files.

Requirements
============
 - Python 3 (or Python >= 2.7)
 - pyOpenSSL
  - Ubuntu: python3-openssl
  - Fedora: python3-pyOpenSSL

Python version
==============

It is made for Python 3.3, but it should be able to run on Python 2.7. 
You'll need to prepend python2.7 to the command (python2.7 ./mysslgen.py)

The ConfigParser module in Python 2.6 does not recognize the "allow_no_value"
option, so Python 2.6 will not work for now.

RHEL6
=====
Enable RedHat Software Collections, there you can find Python 2.7 and Python 3.3

CentOS6
=======
Install the IUS repo: http://www.iuscommunity.org/pages/IUSClientUsageGuide.html
Then:

	yum install python33 python33-distribute gcc openssl-devel
	easy_install-3.3 pyOpenSSL

License
=======
This project is licensed under GPLv2
