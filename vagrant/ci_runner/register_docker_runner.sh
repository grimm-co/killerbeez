# TODO: exit early if already registered
DISTRO=$1
VERSION=$2

# Register the runner
RUNNER_NAME=kb-docker-${DISTRO}-${VERSION}
RUNNER_TAG_LIST=${DISTRO},${DISTRO}-${VERSION}
DOCKER_IMAGE=kb-${DISTRO}-${VERSION}

# Check if already registered
sudo docker run \
    --rm \
    -v /srv/gitlab-runner/config:/etc/gitlab-runner \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /killerbeez:/killerbeez \
    gitlab/gitlab-runner list |& grep -qF "$RUNNER_NAME"

if [[ $? -eq 0 ]]; then
    echo "$RUNNER_NAME already registered, skipping registration"
    exit 0
fi

sudo docker run \
    --rm \
    -e RUNNER_NAME=$RUNNER_NAME \
    -e RUNNER_TAG_LIST=$RUNNER_TAG_LIST \
    -e RUNNER_EXECUTOR=docker \
    -e DOCKER_IMAGE=$DOCKER_IMAGE \
    -e DOCKER_PULL_POLICY=never \
    --env-file /killerbeez/runner_vars \
    -v /srv/gitlab-runner/config:/etc/gitlab-runner \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /killerbeez:/killerbeez \
    gitlab/gitlab-runner register
