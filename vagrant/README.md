These are configuration files and scripts for [Vagrant](https://www.vagrantup.com/).
The scripts will install all necessary dependencies, checkout and build
Killerbeez, and then run some basic tests to make sure it's working as
expected.

They are organized by Linux distribution and version.  To use them, copy the
shell scripts into the distribution you want to run, `cd` into that directory
and run `vagrant up` (assuming Vagrant is installed and configured, obviously).
These should work with any hypervisor, but they have been tested using
VirtualBox as a back end.

For example, to get Killerbeez running on Ubuntu 16.04 (xenial):
```
cp *.sh ubuntu/xenial
cd ubuntu/xenial
vagrant up
```

If you don't want to use Vagrant, the scripts in this directory should still
help get you up and running on your own VM or on a bare-metal installation.
The dependencies.sh script should be run as root, as it'll install the
dependencies.  The setup.sh script should be run as a normal user.

