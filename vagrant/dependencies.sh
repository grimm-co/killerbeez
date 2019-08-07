#!/bin/bash
# Installs dependencies for Debian, Ubuntu, or Fedora

distro=`grep '^ID=' /etc/os-release | sed -e 's/.*=//g'`
version=`grep 'VERSION_ID=' /etc/os-release | sed -e 's/"$//g' -e 's/.*"//g'`

if [[ "$distro" == "debian" ]]; then
	apt-get update
	# Install Debian dependencies
	apt-get -y install llvm clang libtool-bin build-essential cmake automake bison \
		flex libglib2.0-dev libc6-dev-i386 libpixman-1-dev git
elif [[ "$distro" == "fedora" ]]; then
	# Install Fedora dependencies
	dnf -y install llvm clang llvm-devel libtool libstdc++-static cmake bison \
		flex glib2-devel glibc-devel.i686 zlib-devel
elif [[ "$distro" == "ubuntu" ]]; then
	apt-get update
	# Install Ubuntu dependencies
	if [[ "$version" == "14.04" ]]; then
		apt-get -y install llvm clang libtool build-essential cmake automake bison \
			flex libglib2.0-dev libc6-dev-i386 git
	elif [[ "$version" == "16.04" || "$version" == "18.04" || "$version" == "19.04" ]]; then
		apt-get -y install llvm clang libtool-bin build-essential cmake automake bison \
			flex libglib2.0-dev libc6-dev-i386 libpixman-1-dev
	else
		echo "Unsupported version of Ubuntu: $version"
	fi
fi
