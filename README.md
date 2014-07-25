SwiftFS is a userspace filesystem to mount OpenStack container stored in Swift.

Features
--------

* high I/O operations speed
* encryption / decryption
* caching
* multipart parallel upload
* readahead download

Requirements
------------

* glib-2.0 >= 2.32
* fuse >= 2.8.4
* libxml-2.0 >= 2.6
* libcrypto >= 0.9
* libssl >= 0.9
* libevent >= 2.1.2 (development version)

All libraries and versions (except libevent 2.1.2) are compatible with Ubuntu 12.04 LTS.

This is a command line to install all requirements to build this project on Ubuntu:

sudo apt-get install build-essential gcc make automake autoconf libtool pkg-config intltool libglib2.0-dev libfuse-dev libxml2-dev libssl-dev

To install libevent 2.1.2 development version:
* download latest 2.1.x sources from http://libevent.org/
* extract archive
* configure to install it into /opt/libevent2.1 folder:
```
./configure --prefix=/opt/libevent2.1/ --enable-openssl
make && make install
```


How to build SwiftFS
------------------

(if sources are from GitHub): ```sh autogen.sh```
```
PKG_CONFIG_PATH=/opt/libevent2.1/lib/pkgconfig ./configure
make
make install
```

Provide configure script with ```--enable-debug-mode``` flag if you want to get a debug build.
Provide ```--enable-test-apps``` flag if you want to build test applications.

How to start using SwiftFS
------------------------
```
export SwiftFS_USER="Swift username"
export SwiftFS_PWD="Swift password"

swiftfs [http://auth.api.yourcloud.com/v1.0] [options] [container] [mountpoint]
```

Where options are:
```
-v: Verbose output
-f: Do not daemonize process
-c path:  Path to configuration file
-o [opts]: FUSE options, see FUSE manpage
```
Configuration file
------------------

Configuration file (```swiftfs.conf.xml```) is located in ```$(prefix)/etc``` directory.

Bug reporting
-------------

Please include version of SwiftFS and libraries by running:
```
swiftfs --version
```

Certificates
-------------

In order to use HTTPS you need to prepare a PEM certificate, which contains all trusted CA certificates.
For example, if you have 2 different .pem certificates (or .crt), perform the following action:

```
cat 1.pem >> out.pem
cat 2.pem >> out.pem
```

and set path to out.pem in "conenction.ssl_ca_cert" section of configuration file.
