
Description
===========

This is a tool to help and configure MySQL for use with SSL

It will create a certificate authoritity in /etc/mysql/ssl and 
generate a keypair for the server and a keypair for the client.

It will generate the server and client options which must be added to your configuation.

Usage
=====
usage: myssl.py [-h] [--config CONFFILE] [--ssldir SSLDIR]

Manage SSL Certificates for MySQL

optional arguments:
  -h, --help         show this help message and exit
  --config CONFFILE
  --ssldir SSLDIR

Requirements
============

 - pyOpenSSL (Ubuntu: python3-openssl)

License
=======
This project is licensed under GPLv2
