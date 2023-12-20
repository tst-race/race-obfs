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
# Script to build artifacts for the plugin in all possible environments: 
# android client, linux client, and linux server. Once built, move the artifacts
# to the plugin/artifacts dir for publishing to Jfrog Artifactory
# -----------------------------------------------------------------------------


set -e
CALL_NAME="$0"


###
# Helper functions
###


# Load Helper Functions
BASE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)
# shellcheck disable=SC1091
. "${BASE_DIR}/helper_functions.sh"


###
# Arguments
###

# Version values
RACE_VERSION="2.4.1"
PLUGIN_REVISION="latest"

# Build Arguments
VERBOSE=""

HELP=\
"Script to build artifacts for the plugin for all possible environments: 
android client, linux client, and linux server. Once built, move the artifacts
to the plugin/artifacts dir for publishing to Jfrog Artifactory
# NOTE: run in race-sdk container

Build Arguments:
    -c [value], --cmake_args [value], --cmake_args=[value]
        Additional arguments to pass to cmake.
    --race-version [value], --race-version=[value]
        Specify the RACE version. Defaults to '${RACE_VERSION}'.
    --plugin-revision [value], --plugin-revision=[value]
        Specify the Plugin Revision Number. Defaults to '${PLUGIN_REVISION}'.
    --verbose
        Make everything very verbose.

Help Arguments:
    -h, --help
        Print this message

Examples:
    ./build_artifacts.sh --race-version=2.3.0
"

while [ $# -gt 0 ]
do
    key="$1"

    case $key in
        --race-version)
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
        
        --plugin-revision)
        if [ $# -lt 2 ]; then
            formatlog "ERROR" "missing revision number" >&2
            exit 1
        fi
        PLUGIN_REVISION="$2"
        shift
        shift
        ;;
        --plugin-revision=*)
        PLUGIN_REVISION="${1#*=}"
        shift
        ;;

        --verbose)
        VERBOSE="-DCMAKE_VERBOSE_MAKEFILE=ON"
        shift
        ;;

        -h|--help)
        printf "%s" "${HELP}"
        shift
        exit 1;
        ;;
        *)
        formatlog "ERROR" "${CALL_NAME} unknown argument \"$1\""
        exit 1
        ;;
    esac
done

if [ -n "${VERBOSE}" ] ; then
    set -x
fi

###
# Main Execution
###

formatlog "INFO" "Cleaning plugin/artifacts Before Building Artifacts"
bash "${BASE_DIR}/clean_artifacts.sh"

if [ "$(uname -m)" == "x86_64" ]
then
    formatlog "INFO" "Building Linux x86_64 Client/Server"
    cmake --preset=LINUX_x86_64 -Wno-dev \
        -DBUILD_VERSION="${RACE_VERSION}-${PLUGIN_REVISION}"
    # This will copy the output to plugin/artifacts/linux-x86_64-server
    cmake --build --preset=LINUX_x86_64
elif [ "$(uname -m)" == "aarch64" ]
then
    formatlog "INFO" "Building Linux arm64-v8a Client/Server"
    cmake --preset=LINUX_arm64-v8a -Wno-dev \
        -DBUILD_VERSION="${RACE_VERSION}-${PLUGIN_REVISION}"
    # This will copy the output to plugin/artifacts/linux-arm64-v8a-server
    cmake --build --preset=LINUX_arm64-v8a
else
    formatlog "ERROR" "unsupported architecture: $(uname -m)"
    exit 1
fi
