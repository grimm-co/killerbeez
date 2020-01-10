distro=`grep '^ID=' /etc/os-release | sed -e 's/.*=//g'`
version=`grep 'VERSION_ID=' /etc/os-release | sed -e 's/"$//g' -e 's/.*"//g' -e 's/^VERSION_ID=//g'`

# Set up repository
if [[ "$distro" == "debian" || "$distro" == "ubuntu" ]]; then
	# For Debian/Ubuntu/Mint
	curl -L https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.deb.sh | sudo bash
elif [[ "$distro" == "fedora" ]]; then
	# For RHEL/CentOS/Fedora
	curl -L https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.rpm.sh | sudo bash
fi

# Create apt pin for debian
if [[ "$distro" == "debian" ]]; then
cat <<EOF | sudo tee /etc/apt/preferences.d/pin-gitlab-runner.pref
Explanation: Prefer GitLab provided packages over the Debian native ones
Package: gitlab-runner
Pin: origin packages.gitlab.com
Pin-Priority: 1001
EOF
fi

# Install runner package
if [[ "$distro" == "debian" || "$distro" == "ubuntu" ]]; then
	# For Debian/Ubuntu/Mint
	sudo apt-get update
	sudo apt-get install -y gitlab-runner
elif [[ "$distro" == "fedora" ]]; then
	# For RHEL/CentOS/Fedora
	sudo yum install -y gitlab-runner

        # Disable SELinux
        sudo sed -i /etc/selinux/config -e 's/^SELINUX=enforcing/SELINUX=permissive/g'
        sudo setenforce 0
fi

# Check if already registered
RUNNER_NAME=kb-${distro}-${version}
RUNNER_TAG_LIST=${distro},${distro}-${version}

sudo gitlab-runner list |& grep -qF "$RUNNER_NAME"

if [[ $? -eq 0 ]]; then
    echo "$RUNNER_NAME already registered, skipping registration"
    exit 0
fi

# Register the runner
sudo env $(cat /killerbeez/runner_vars | xargs) \
    RUNNER_NAME=$RUNNER_NAME RUNNER_TAG_LIST=$RUNNER_TAG_LIST RUNNER_EXECUTOR=shell \
    gitlab-runner register
