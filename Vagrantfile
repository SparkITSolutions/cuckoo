# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure("2") do |config|
  # The most common configuration options are documented and commented below.
  # For a complete reference, please see the online documentation at
  # https://docs.vagrantup.com.

  # Every Vagrant development environment requires a box. You can search for
  # boxes at https://vagrantcloud.com/search.
  config.vm.box = "generic/ubuntu1604"

  # Disable automatic box update checking. If you disable this, then
  # boxes will only be checked for updates when the user runs
  # `vagrant box outdated`. This is not recommended.
  # config.vm.box_check_update = false

  # Create a forwarded port mapping which allows access to a specific port
  # within the machine from a port on the host machine. In the example below,
  # accessing "localhost:8080" will access port 80 on the guest machine.
  # NOTE: This will enable public access to the opened port
  # config.vm.network "forwarded_port", guest: 80, host: 8080

  # Create a forwarded port mapping which allows access to a specific port
  # within the machine from a port on the host machine and only allow access
  # via 127.0.0.1 to disable public access
  # config.vm.network "forwarded_port", guest: 80, host: 8080, host_ip: "127.0.0.1"

  # Create a private network, which allows host-only access to the machine
  # using a specific IP.
  # config.vm.network "private_network", ip: "192.168.33.10"

  # Create a public network, which generally matched to bridged network.
  # Bridged networks make the machine appear as another physical device on
  # your network.
  # config.vm.network "public_network"

  # Share an additional folder to the guest VM. The first argument is
  # the path on the host to the actual folder. The second argument is
  # the path on the guest to mount the folder. And the optional third
  # argument is a set of non-required options.
  # config.vm.synced_folder "../data", "/vagrant_data"

  # Provider-specific configuration so you can fine-tune various
  # backing providers for Vagrant. These expose provider-specific options.
  # Example for VirtualBox:
  #
  # config.vm.provider "virtualbox" do |vb|
  #   # Display the VirtualBox GUI when booting the machine
  #   vb.gui = true
  #
  #   # Customize the amount of memory on the VM:
  #   vb.memory = "1024"
  # end
  #
  # View the documentation for the provider you are using for more
  # information on available options.

  # Enable provisioning with a shell script. Additional provisioners such as
  # Puppet, Chef, Ansible, Salt, and Docker are also available. Please see the
  # documentation for more information about their specific syntax and use.
   config.vm.provision "shell", inline: <<-SHELL
  #   apt-get update
  #   apt-get install -y apache2
  #!/bin/bash
  CUCKOO_USER="cuckoo"
  echo "Cloning phoenix"
  if [ -z "$(which git)" ]; then
      apt-get -y install git
  fi
  if [ -z "$(which add-apt-repository)" ]; then
      apt-get -y install software-properties-common
  fi
  git clone https://github.com/SparkITSolutions/cuckoo.git /opt/phoenix
  ## We used to import ova files, but then you have to setup snapshots.  We're lazy...
  ## You can still have the easy-button import your OVAs, but then you'll have to do stuff like this later to setup snapshots:
  ##
  ## su - cuckoo
  ## vboxmanage modifyvm win7-x86-0 --vrde on
  ## vboxmanage modifyvm win7-x86-0 --vrdeaddress 127.0.0.1
  ## vboxmanage modifyvm win7-x86-0 --vrdeport 3389
  ## vboxheadless -v on -e authType=NULL -s $$VMNAME
  ##
  #cp /data/staging/vms/*.ova /opt/phoenix/install/virtualbox/
  echo "Copying staging VMs"
  cp /data/staging/VirtualBoxVMs.gz /opt/phoenix/install/virtualbox/
  echo "Copying openvpn files"
  cp /data/staging/openvpn/* /opt/phoenix/install/openvpn/
  cd /opt/phoenix/install
  echo "Installing phoenix"
  ## This is where the magic happens...
  bash ubuntu_install.sh
  ## Copy the virtualbox config from your existing Cuckoo deployment into Phoenix
  cp /data/staging/virtualbox.conf /opt/phoenix/conf/
  chown $CUCKOO_USER.$CUCKOO_USER /opt/phoenix/conf/*
  ## Restart all of your newly installed Cuckoo services
  /opt/phoenix/utils/crontab/root/cuckoo_full_restart.sh
  ## Go get your miscreant punch on!!!
```

  # SHELL
end
