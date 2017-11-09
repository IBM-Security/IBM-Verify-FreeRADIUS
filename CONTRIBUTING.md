<img src="logo.png" align="right" width="250px" />

# Contributing to ISAM FreeRADIUS
Just submit a pull request. Jared (<jaredpa@au1.ibm.com>) will be the approver. However, to make a change that you can assure is valid you will need to be able to build FreeRADIUS from source and run through the changes. There are no formal test cases at this point - just tell me that you tested in runtime and I'll accept the pull request. 

## Building from Source

If you want to build from source, then you need to download the FreeRadius source tree first. This is hosted on GitHub [here](https://github.com/FreeRADIUS/freeradius-server). 
Once you have this structure - copy the [rlm_isam](src/rlm_isam) folder into freeradius-server/src/modules/rlm_isam. You'll need to run the configure script. Then you can make the server.

### Vagrant Build Environment
1. Install [Vagrant](https://www.vagrantup.com/downloads.html)
2. Stand up the vagrant environment (this may take a while to download the images):
```
vagrant plugin install vagrant-vbguest
vagrant up
vagrant ssh
```

After this - the complete build environment will be ready to go in CentOS 7 in the freeradius-server/ folder. 

Important files will be:
- The Radius configuration file:
	- /usr/local/etc/raddb/radiusd.conf
- The Clients configuration file:
	- /usr/local/etc/raddb/clients.conf
- The authorize server file:	
	- /usr/local/etc/raddb/mods-config/files/authorize
- The default sites-available configuration file:
	- /usr/local/etc/raddb/sites-available/default
- The location of the source of ISAM FreeRADIUS (This has 5 main files; rlm_isam.c, rlm_isam.h, isam.c, isam.h and the make file all.mk):
	- /home/vagrant/freeradius-server/src/modules/rlm_isam

### MacOS (10.12)

```
git clone https://github.com/FreeRADIUS/freeradius-server.git
git checkout release_3_0_11 (issue)[https://github.com/FreeRADIUS/freeradius-server/issues/1636]
./configure
make
make install
Some libpcre problem
```

### CentOS
```
sudo yum update -y
sudo yum install gcc openssl-devel.x86_64 git libtalloc-devel -y  
git clone https://github.com/FreeRADIUS/freeradius-server.git
cd freeradius-server/
git checkout release_3_0_11 #(issue)[https://github.com/FreeRADIUS/freeradius-server/issues/1636]
sudo ./configure
sudo make
sudo make install
cd ../
sudo chown -R vagrant freeradius-server/
sudo chgrp -R vagrant freeradius-server/
sudo chgrp -R vagrant /usr/local/etc/raddb/
sudo chown -R vagrant /usr/local/etc/raddb/
```

Copy the src/rlm_isam folder in this repository into the freeradius-server/src/modules/ folder. 
Since CentOS 7 is using an insecure version of OpenSSL - you'll have to change a setting in the radius configuration: 
```
# SECURITY CONFIGURATION
#
#  There may be multiple methods of attacking on the server.  This
#  section holds the configuration items which minimize the impact
#  of those attacks
#
security {
     allow_vulnerable_openssl = 'CVE-2014-0160'
}
```

If you don't want to do this - you can install the latest version of OpenSSL (these steps aren't kept updated):
	
```
sudo yum install wget -y
wget http://www.openssl.org/source/openssl-1.0.2l.tar.gz
tar xzvf openssl-1.0.2l.tar.gz
cd openssl-1.0.2l/
sudo ./config
sudo make
sudo make install
sudo cp /usr/local/ssl/bin/openssl /usr/bin/
cd ../
sudo rm -r openssl-1.0.2l/
sudo rm openssl-1.0.2l.tar.gz
./configure --with-openssl-lib-dir=/usr/local/ssl/lib/ --with-openssl-include-dir=/usr/local/ssl/include/
```

If you have the Minimal CentOS build, then you may have to do the following BEFORE you run ./configure:

- Make sure your network is setup:
```
nmcli d
nmtui (Set connection to automatically connect)
service network restart
```

- Install [CMAKE](https://xinyustudio.wordpress.com/2014/06/18/how-to-install-cmake-3-0-on-centos-6-centos-7/)
```
wget http://www.cmake.org/files/LatestRelease/cmake-3.8.0-rc1.tar.gz (releases)[https://cmake.org/files/LatestRelease/]
tar -zxvf cmake-3.8.0-fc1.tar.gz
cd cmake-3.8.0-rc1
./bootstrap
gmake
gmake install
```

- Install libjsoncpp
Might be able to run yum install libjsoncpp-dev or yum install jsoncpp-devl, however if that doesn't work:
```
sudo yum install libjsoncpp-dev
sudo yum install jsoncpp-devl
git clone https://github.com/open-source-parsers/jsoncpp.git (helpful link)[http://ask.xmodulo.com/fix-fatal-error-jsoncpp.html]
cd jsoncpp
mkdir -p build/debug
cd build/debug
cmake -DCMAKE_BUILD_TYPE=debug -DJSONCPP_LIB_BUILD_SHARED=OFF -G "Unix Makefiles" ../../
make
sudo make install
```

- Install [libkqueue](https://github.com/mheily/libkqueue)
```
cmake -G "Unix Makefiles" -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_LIBDIR=lib <path to source>
make
make install
```

### Debugging 
- GDB for general debugging, this is installed already in the Valgrind environment. Unfortunately this doesn't work on MacOS.
- Valgrind - At the time of writing, there was an issue with Valgrind and the way it way allowed to read other processess information. This caused Valgrind itself to seg fault on occasion. This bug is detailed 
[here](https://www.mail-archive.com/kde-bugs-dist@kde.org/msg136799.html). I tried to manually apply the patch the user submitted - but it didn't fix the problem. 