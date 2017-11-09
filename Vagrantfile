# # -*- mode: ruby -*-
# # vi: set ft=ruby :

# # All Vagrant configuration is done below. The "2" in Vagrant.configure
# # configures the configuration version (we support older styles for
# # backwards compatibility). Please don't change it unless you know what
# # you're doing.
# Vagrant.configure("2") do |config|
#   # The most common configuration options are documented and commented below.
#   # For a complete reference, please see the online documentation at
#   # https://docs.vagrantup.com.

#   # Every Vagrant development environment requires a box. You can search for
#   # boxes at https://vagrantcloud.com/search.
#   config.vm.box = "centos/7"

#   # Disable automatic box update checking. If you disable this, then
#   # boxes will only be checked for updates when the user runs
#   # `vagrant box outdated`. This is not recommended.
#   # config.vm.box_check_update = false

#   # Create a forwarded port mapping which allows access to a specific port
#   # within the machine from a port on the host machine. In the example below,
#   # accessing "localhost:8080" will access port 80 on the guest machine.
#   # NOTE: This will enable public access to the opened port
#   # config.vm.network "forwarded_port", guest: 80, host: 8080

#   # Create a forwarded port mapping which allows access to a specific port
#   # within the machine from a port on the host machine and only allow access
#   # via 127.0.0.1 to disable public access
#   # config.vm.network "forwarded_port", guest: 80, host: 8080, host_ip: "127.0.0.1"

#   # Create a private network, which allows host-only access to the machine
#   # using a specific IP.
#   config.vm.network "private_network", ip: "88.111.88.11"
#   config.vm.hostname = "radius"
#   config.ssh.forward_agent = true

#   # Create a public network, which generally matched to bridged network.
#   # Bridged networks make the machine appear as another physical device on
#   # your network.
#   # config.vm.network "public_network"

#   # Share an additional folder to the guest VM. The first argument is
#   # the path on the host to the actual folder. The second argument is
#   # the path on the guest to mount the folder. And the optional third
#   # argument is a set of non-required options.
#   # config.vm.synced_folder "../data", "/vagrant_data"

#   # Provider-specific configuration so you can fine-tune various
#   # backing providers for Vagrant. These expose provider-specific options.
#   # Example for VirtualBox:
#   #
#   # config.vm.provider "virtualbox" do |vb|
#   #   # Display the VirtualBox GUI when booting the machine
#   #   vb.gui = true
#   #
#   #   # Customize the amount of memory on the VM:
#   #   vb.memory = "1024"
#   # end
#   #
#   # View the documentation for the provider you are using for more
#   # information on available options.

#   # Enable provisioning with a shell script. Additional provisioners such as
#   # Puppet, Chef, Ansible, Salt, and Docker are also available. Please see the
#   # documentation for more information about their specific syntax and use.
#   # config.vm.provision "shell", inline: <<-SHELL
#   #   apt-get update
#   #   apt-get install -y apache2
#   # SHELL
#   #git clone https://github.com/FreeRADIUS/freeradius-server.git
#   #git checkout release_3_0_4

#   config.vm.provision "shell", inline: <<-SHELL
#       sudo yum update -y
#       sudo yum install gcc wget openssl-devel.x86_64 git libtalloc-devel libcurl-devel -y  
#       wget https://github.com/FreeRADIUS/freeradius-server/archive/release_3_0_4.tar.gz
#       sudo mkdir freeradius-server
#       sudo tar xzvf release_3_0_4.tar.gz -C freeradius-server/ --strip-components=1
#       sudo rm release_3_0_4.tar.gz
#       cd freeradius-server/
#       sudo ./configure
#       sudo make
#       sudo make install
#       cd ../
#       sudo chown -R vagrant freeradius-server/
#       sudo chgrp -R vagrant freeradius-server/
#       cd /home/vagrant/
#       sudo chgrp -R vagrant /usr/local/etc/raddb/
#       sudo chown -R vagrant /usr/local/etc/raddb/
#   SHELL

#   config.vm.provision "file", source: "configuration/radiusd.conf", destination: "/usr/local/etc/raddb/radiusd.conf"
#   config.vm.provision "file", source: "configuration/clients.conf", destination: "/usr/local/etc/raddb/clients.conf"
#   config.vm.provision "file", source: "configuration/authorize", destination: "/usr/local/etc/raddb/mods-config/files/authorize"
#   config.vm.provision "file", source: "configuration/default", destination: "/usr/local/etc/raddb/sites-available/default"
#   config.vm.provision "file", source: "src/rlm_isam", destination: "/home/vagrant/freeradius-server/src/modules/rlm_isam"
#   config.vm.provision "file", source: "src/rlm_isam/all.mk", destination: "/home/vagrant/freeradius-server/src/modules/rlm_isam/all.mk"
#   # config.vm.provision "file", source: "configuration/filter", destination: "/usr/local/etc/raddb/policy.d/filter"

#   config.vm.provision "shell", inline: <<-SHELL
#       cd freeradius-server/
#       sudo make clean
#       sudo make
#       sudo make install
#       sudo chgrp -R vagrant /usr/local/etc/raddb/
#       sudo chown -R vagrant /usr/local/etc/raddb/
#   SHELL

#   config.vm.synced_folder ".", "/vagrant", type: "virtualbox"
#   config.vm.synced_folder "./", "/home/vagrant/shared", create: true, group: "vagrant", owner: "vagrant"
# end

#fakeroot dpkg-buildpackage -b -uc
#cd freeradius-server-release_#{version}/

# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = "2"

version="3_0_4"
version="3_0_13"
# version="4_0_0"

# image="ubuntu/trusty64"
# image="ubuntu/xenial64"
image="centos/7"


ubuntu_script = <<SCRIPT

apt-get update -y
apt-get install -y git ssl-cert autotools-dev libgdbm-dev libpcap-dev libsqlite3-dev dpkg-dev debhelper quilt libcurl4-openssl-dev libiodbc2-dev libjson-c-dev libjson0-dev libkrb5-dev libldap2-dev libpam0g-dev libperl-dev libmysqlclient-dev libpq-dev libreadline-dev libsasl2-dev libtalloc-dev libyubikey-dev python-dev

SCRIPT

centos_script = <<SCRIPT

sudo yum update -y
sudo yum install gcc wget openssl-devel.x86_64 git libtalloc-devel libcurl-devel -y

SCRIPT

compile_script = <<SCRIPT

mkdir freeradius-server

wget https://github.com/FreeRADIUS/freeradius-server/archive/release_#{version}.tar.gz

tar zxf release_#{version}.tar.gz -C freeradius-server/ --strip-components=1

rm release_#{version}.tar.gz

cd freeradius-server/

sudo ./configure
sudo make clean
sudo make
sudo make install
 
cd ../

sudo chown -R vagrant freeradius-server/
sudo chgrp -R vagrant freeradius-server/

cd /home/vagrant/      

sudo chgrp -R vagrant /usr/local/etc/raddb/
sudo chown -R vagrant /usr/local/etc/raddb/

SCRIPT

make_script = <<SCRIPT

  cd freeradius-server/
  sudo make clean
  sudo make
  sudo make install

SCRIPT

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  
  config.vm.box = "#{image}"

  config.vm.network "private_network", ip: "88.111.88.11"
  config.vm.network "forwarded_port", guest: 1812, host: 18129
  config.vm.hostname = "isam-freeradius"
  
  config.vm.provision "shell", inline: centos_script 
  config.vm.provision "shell", inline: compile_script 

  config.vm.provision "file", source: "configuration/radiusd_#{version}.conf", destination: "/usr/local/etc/raddb/radiusd.conf"
  config.vm.provision "file", source: "configuration/clients.conf", destination: "/usr/local/etc/raddb/clients.conf"
  # config.vm.provision "file", source: "configuration/authorize", destination: "/usr/local/etc/raddb/mods-config/files/authorize"
  # config.vm.provision "file", source: "configuration/default", destination: "/usr/local/etc/raddb/sites-available/default"
  config.vm.provision "file", source: "src/rlm_verify", destination: "/home/vagrant/freeradius-server/src/modules/rlm_verify"
  config.vm.provision "file", source: "src/rlm_verify/all.mk", destination: "/home/vagrant/freeradius-server/src/modules/rlm_verify/all.mk"
  # config.vm.provision "file", source: "configuration/filter#{version}", destination: "/usr/local/etc/raddb/policy.d/filter"

  config.vm.provision "shell", inline: make_script 

  config.vm.synced_folder ".", "/vagrant", type: "virtualbox"
  config.vm.synced_folder "./", "/home/vagrant/shared", create: true, group: "vagrant", owner: "vagrant"

end
