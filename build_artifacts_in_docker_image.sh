#!/usr/bin/env bash

# 
# Copyright 2023 Two Six Technologies
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 

# -----------------------------------------------------------------------------
# This script starts a docker container that will be used for building the RACE
# plugin. By default, the build_artifacts.sh script is run inside the docker container.
# Optionally, additional arguments to docker run may be provided, or a different
# command may be run instead of build (such as a shell).
# -----------------------------------------------------------------------------

set -e
CALL_NAME="$0"


###
# Helper functions
###


# Load Helper Functions
CURRENT_DIR=$(cd $(dirname ${BASH_SOURCE[0]}) >/dev/null 2>&1 && pwd)
. ${CURRENT_DIR}/helper_functions.sh

# TODO: should we update this script or just delete it?

###
# Arguments
###


# Override Args
DOCKER_ARGS=""
BUILD_ARGS=""

FILEPATH="$(pwd)"

# Docker Image Values
RACE_CONTAINER_REGISTRY="ghcr.io"
RACE_GITHUB_GROUP="tst-race"
RACE_COMPILE_IMAGE_REPO="race-core"
RACE_COMPILE_IMAGE_NAME="raceboat-compile"
LOCAL=false

# Version values
RACE_VERSION="2.6.0"

COMMAND="./build_artifacts.sh"

HELP=\
'This script starts a docker container that will be used for building the RACE
plugin. By default, the build_artifacts.sh script is run inside the docker container.
Optionally, additional arguments to docker run may be provided, or a different
command may be run instead of build (such as a shell).

Arguments:
    -a [value], --args [value], --args=[value]
        Additional arguments to pass to docker when running the container.
    -b [value], --build-args [value], --build-args=[value]
        Additional arguments to pass to the command used when running the
        container. By default this is the build script. This may be used to
        build specific targets. Alternatively, -- may be used to terminate the
        list of arguments given to this script and the rest will be given to the
        run command.
    -f [value], --filepath [value], --filepath=[value]
        The location to mount into the build container. By default this is the
        current directory.
    -l, --local
        Use a local image, instead of one from the container repository
    -g [value], --group [value], --group=[value]
        Specify a github group for the container registry. Defaults to '${RACE_GITHUB_GROUP}'.
    -v [value], --race-version [value], --race-version=[value]
        Specify the RACE version. Defaults to '${RACE_VERSION}'.
    -h, --help
        Print this message.
    --
        Terminate the list of arguments given to this script and give any
        following arguments to the run command.

Examples: 
    ./build_artifacts_in_docker_image.sh -c bash
    ./build_artifacts_in_docker_image.sh --race-version=2.6.0
    ./build_artifacts_in_docker_image.sh -- --verbose -j 1
    ./build_artifacts_in_docker_image.sh -- -h

'

# Parse CLI Arguments
while [ $# -gt 0 ]
do
    key="$1"

    case $key in
        -a|--args)
        DOCKER_ARGS="$2"
        shift
        shift
        ;;
        --args=*)
        DOCKER_ARGS="${1#*=}"
        shift
        ;;

        -b|--build-args)
        BUILD_ARGS="$2"
        shift
        shift
        ;;
        --build-args=*)
        BUILD_ARGS="${1#*=}"
        shift
        ;;

        -c|--command)
        COMMAND="$2"
        shift
        shift
        ;;
        --command=*)
        COMMAND="${1#*=}"
        shift
        ;;


        -f|--filepath)
        FILEPATH="$2"
        shift
        shift
        ;;
        --filepath=*)
        FILEPATH="${1#*=}"
        shift
        ;;

        -g|--group)
        if [ $# -lt 2 ]; then
            formatlog "ERROR" "missing group" >&2
            exit 1
        fi
        RACE_GITHUB_GROUP="$2"
        shift
        shift
        ;;
        --group=*)
        RACE_GITHUB_GROUP="${1#*=}"
        shift
        ;;

        -v|--race-version)
        if [ $# -lt 2 ]; then
            formatlog "ERROR" "missing RACE version number" >&2
            exit 1
        fi
        RACE_VERSION="$2"
        shift
        shift
        ;;
        --race-version=*)
        RACE_VERSION="${1#*=}"
        shift
        ;;

        -l|--local)
        LOCAL=true
        shift
        ;;

        -h|--help)
        printf "%s" "${HELP}"
        exit 1;
        ;;

        --*)
        shift
        break
        ;;
        *)
        formatlog "ERROR" "${CALL_NAME} unknown argument \"$1\""
        exit 1
        ;;
    esac
done


###
# Main Execution
###


if [ "${LOCAL}" = true ]; then
    RACE_COMPILE_IMAGE="${RACE_COMPILE_IMAGE_NAME}:${RACE_VERSION}"
else
    RACE_COMPILE_IMAGE="${RACE_CONTAINER_REGISTRY}/${RACE_GITHUB_GROUP}/${RACE_COMPILE_IMAGE_REPO}/${RACE_COMPILE_IMAGE_NAME}:${RACE_VERSION}"
    docker pull "${RACE_COMPILE_IMAGE}"
fi

formatlog "INFO" "Using image ${RACE_COMPILE_IMAGE}"
docker inspect -f '{{ .Created }}' "${RACE_COMPILE_IMAGE}"

formatlog "INFO" "Running Docker Container and Running Build Command"
docker run --rm \
    -v "${FILEPATH}":/code \
    -w /code \
    --name "plugin_builder_golang_comms" \
    ${DOCKER_ARGS} \
    "${RACE_COMPILE_IMAGE}" \
    "${COMMAND}" ${BUILD_ARGS} "$@"
