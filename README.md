
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

Requirements
============
 - Python
 - pyOpenSSL (Ubuntu: python3-openssl)

It is made for Python 3.3, but it should be able to run on Python 2.7. 
You'll need to prepend python2.7 to the command (python2.7 ./mysslgen.py)

License
=======
This project is licensed under GPLv2
