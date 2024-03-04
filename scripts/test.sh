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


# Script for verifying that the project will build. Creates a container and runs the build commands. Should be run from your host machine.

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd $DIR/..

CONTAINER_CODE_MOUNT_POINT="/code/project"
TEST_COMMAND="set -e; cd test/cpp-app; make; ./cpp-test-app"
IMAGE="ghcr.io/tst-race/race-images/race-sdk:latest"
CONTAINER_NAME="race-tester-plugin-comms-twosix-golang"

docker pull "${IMAGE}"

docker run -it --rm \
    -v $(pwd):$CONTAINER_CODE_MOUNT_POINT \
    -w="${CONTAINER_CODE_MOUNT_POINT}" \
    --name=$CONTAINER_NAME \
    $IMAGE \
    bash -c "$TEST_COMMAND"
