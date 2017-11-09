<img src="logo.png" align="right" width="250px" />

# ISAM FreeRadius
ISAM FreeRadius module for enhanced authentication.

## Quick start
To use this repository, you must have already setup SSH keys to the IBM Github. See a guide [here](https://help.github.com/articles/adding-a-new-ssh-key-to-your-github-account/). You must also already have either Vagrant or Docker & Docker Compose installed. 
```
git clone git@github.ibm.com:jaredpa/ISAM-FreeRadius.git
cd ISAM-FreeRadius/
```
For normal production usage: 
```
docker-compose up -d
```
or if you want a development environment (See [Building from Source](#building-from-source) for more info):
```
vagrant up
```

### Verification testing
Run through the [Shell Test Client](#shell-test-client) section and verify that the mode you have selected works.

## Shell Test Client
```
~/ISAM-FreeRadius $ sh test_isam_radius.sh
usage: test_isam_radius.sh <mode> <host> <port> <secret> <user> <otp:OPTIONAL>
```
Example usage:
```
sh test_isam_radius.sh multi localhost 1812 testing123 jaredpa@au1.ibm.com
```

What I usually do for testing/development is:

Run this in one terminal window:

```
make install; /usr/local/sbin/radiusd -X
```

and then in another terminal window, run the test client:

```
sh test_isam_radius.sh multi localhost 1812 testing123 jaredpa@au1.ibm.com
```

## Modes

This module will support 3 modes (configurable via the [radiusd.conf](configuration/radiusd.conf) file) that will determine the functionality for an end user. 
The module **cannot** do all these 3 modes at once, however multi can be aliased to be very similar to simple. In addition, some Radius client programs do not support the
ability to handle the radius 'Accept-Challenge' response and present information to the user appropriately. This is not a limitation of this module but rather the client. 

### 1) Simple
A user will provide their username, password and OTP combination as a single field like:

```
username: testuser
password: passw0rd1234
```

Where the last 4-6 characters is the OTP. 

### 2) Multi
A user will provide their username, password and OTP combination on prompt. An example of this is:

```
username: testuser
password: passw0rd
otp: 1234
```

This could change if there was no OTP required (by CBA policy for example).

### 3) Interactive
A user will provide their username, password and select from modes of authentication:

```
username: testuser
password: passw0rd

1. SMS
2. TOTP
3. Verify

verify

Waiting for you to approve on your linked device...
```

This flow allows a user to select HOW they would like to present their second factor of authentication. 

## Compatible Radius Clients

The following radius clients have been tested against. This is not a exhaustive list, as the module may work with others. 

Client Name | Status | Description
------------ | ------------- | -------------
[radclient](https://wiki.freeradius.org/config/Radclient) | TESTED | This is the core utility officially provided by FreeRADIUS to test Radius UDP calls. 
[VMWare Horizon](https://www.vmware.com/products/horizon.html) | NOT TESTED | This module has not been tested. It appears to support interactive mode though
[Radius.NET](https://github.com/frontporch/Radius.NET) | NOT TESTED | This module has not been tested. 

## Existing installation setup
This section is for those who have an existing FreeRADIUS installation and want to use the ISAM-FreeRadius module. 
### Install
1. Stop your FreeRADIUS server. 
2. Copy the provided [rlm_isam.so](output/rlm_isam.so) file into your FreeRADIUS installation module path. On CentOS this is at /usr/lib64/freeradius/. Make sure it has the same permissions and user/group permissions as the files around it. 
3. Add the module into the radiusd.conf [/usr/local/etc/raddb/radiusd.conf](configuration/radiusd.conf)
4. Make sure your client and client secret is in clients.conf [/usr/local/etc/raddb/clients.conf](configuration/clients.conf). The test scripts provided use the client secret of 'example_isam_secret'.
5. In the authorize stanza of the available sites for the radius server (default..by default), add the module 'isam' [/usr/local/etc/raddb/sites-available/default](configuration/default) in the order you'd like it to be processed. 
```
authorize {
	# There will be a bunch of other modules here configured by default - you may remove these.
	isam
}
```
6. Start your FreeRADIUS server. 

## Building from Source
See [CONTRIBUTING](CONTRIBUTING.md).

## Contributing
See [CONTRIBUTING](CONTRIBUTING.md).

## License
See [LICENSE](LICENSE).
