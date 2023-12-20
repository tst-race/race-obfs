
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

cmake_minimum_required(VERSION 3.10)

################################################################################
# Config gen util library
################################################################################
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -v")

set(LIB_PREFIX libObfsConfig)
set(LIB_NAME ${LIB_PREFIX}.so)
set(LIB_PATH ${CMAKE_CURRENT_BINARY_DIR}/${LIB_NAME})

set(GOCMD go build -work -buildmode=c-shared -o ${LIB_PATH})

if(TARGET commsPluginBindingsGolang)
    get_target_property(COMMS_PLUGIN_BINDINGS_GOLANG_BINARY_DIR commsPluginBindingsGolang BINARY_DIR)
    set(COMMS_PLUGIN_BINDINGS_GOLANG_GOPATH ${COMMS_PLUGIN_BINDINGS_GOLANG_BINARY_DIR}/include)
endif()

if(ANDROID)
    # Setup common GOENV variables
    list(APPEND GOENV
        CC=${ANDROID_TOOLCHAIN_ROOT}/bin/${CMAKE_LIBRARY_ARCHITECTURE}${ANDROID_PLATFORM}-clang
        CXX=${ANDROID_TOOLCHAIN_ROOT}/bin/${CMAKE_LIBRARY_ARCHITECTURE}${ANDROID_PLATFORM}-clang++
        GOOS=android
        CGO_ENABLED=1
    )

    if ("${TARGET_ARCHITECTURE}" STREQUAL "ANDROID_x86_64")
        list(APPEND CGO_CXXFLAGS "-I/android/x86_64/include")
        list(APPEND CGO_LDFLAGS "-L/android/x86_64/lib")
        list(APPEND GOENV
            GOPATH=/android/x86_64/go:${COMMS_PLUGIN_BINDINGS_GOLANG_GOPATH}
            GOARCH=amd64
        )
    else()
        list(APPEND CGO_CXXFLAGS "-I/android/arm64-v8a/include")
        list(APPEND CGO_LDFLAGS "-L/android/arm64-v8a/lib")
        list(APPEND GOENV
            GOPATH=/android/arm64-v8a/go:${COMMS_PLUGIN_BINDINGS_GOLANG_GOPATH}
            GOARCH=arm64
        )
    endif()

else()
    list(APPEND CGO_LDFLAGS "-L/usr/local/lib")
    list(APPEND GOENV GOPATH=/go:/usr/local/go:${COMMS_PLUGIN_BINDINGS_GOLANG_GOPATH})
    if ("${TARGET_ARCHITECTURE}" STREQUAL "LINUX_arm64-v8a")
        list(APPEND CGO_CXXFLAGS "-I/linux/arm64-v8a/include")
        list(APPEND CGO_LDFLAGS "-L/linux/arm64-v8a/lib")
        list(APPEND GOENV
            "CC=clang -target aarch64-linux-gnu"
            "CXX=clang++ -target aarch64-linux-gnu"
        )
        list(APPEND GOCMD -ldflags "-linkmode=external '-extldflags=-target aarch64-linux-gnu'")
        list(APPEND GOENV GOARCH=arm64)
    else()
        list(APPEND GOENV
            "CC=clang -target x86_64-linux-gnu"
            "CXX=clang++ -target x86_64-linux-gnu"
        )
        list(APPEND GOCMD -ldflags "-linkmode=external '-extldflags=-target x86_64-linux-gnu'")
        list(APPEND CGO_CXXFLAGS "-I/linux/x86_64/include")
        list(APPEND CGO_LDFLAGS "-L/linux/x86_64/lib")
        list(APPEND GOENV GOARCH=amd64)
    endif()
endif()

# Set common CXX/LD flags
list(APPEND CGO_CXXFLAGS
    -DBUILD_VERSION=\"${BUILD_VERSION}\"
    -I${CMAKE_CURRENT_BINARY_DIR}
)

if(TARGET commsPluginBindingsGolang)
    get_target_property(COMMS_PLUGIN_BINDINGS_GOLANG_INCLUDE_DIRECTORIES commsPluginBindingsGolang INCLUDE_DIRECTORIES)
    foreach (include_dir ${COMMS_PLUGIN_BINDINGS_GOLANG_INCLUDE_DIRECTORIES})
    list(APPEND CGO_CXXFLAGS
        -I${include_dir}
    )
    endforeach()

    get_target_property(COMMS_PLUGIN_BINDINGS_GOLANG_BINARY_DIR commsPluginBindingsGolang BINARY_DIR)
    list(APPEND CGO_LDFLAGS -L${COMMS_PLUGIN_BINDINGS_GOLANG_BINARY_DIR})
endif()


# Convert array variables to strings
string(REPLACE ";" " " CGO_CXXFLAGS "${CGO_CXXFLAGS}")
string(REPLACE ";" " " CGO_LDFLAGS "${CGO_LDFLAGS}")

list(APPEND GOENV
    CGO_CXXFLAGS=${CGO_CXXFLAGS}
    CGO_LDFLAGS=${CGO_LDFLAGS}
)

add_custom_command(
    COMMAND ${CMAKE_COMMAND} -E env ${GOENV} ${GOCMD}
    OUTPUT ${LIB_NAME}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    VERBATIM
)
add_custom_target(ObfsConfig ALL DEPENDS ${LIB_NAME})

message("CMAKE_CURRENT_BINARY_DIR: ${CMAKE_CURRENT_BINARY_DIR}")
message("LIB_PATH: ${LIB_PATH}")

# install in the config gen dir
add_custom_command(TARGET ObfsConfig POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/../plugin/channels/obfs/
    COMMAND ${CMAKE_COMMAND} -E copy ${LIB_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/../plugin/channels/obfs/
)
set_property(DIRECTORY PROPERTY ADDITIONAL_MAKE_CLEAN_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/../plugin/channels/obfs
)


add_custom_target(format_PluginCommsTwoSixGolangConfig
    COMMAND gofmt -w ${CMAKE_CURRENT_SOURCE_DIR}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Formatting PluginCommsTwoSixGolangConfig files..."
)

add_custom_target(check_format_PluginCommsTwoSixGolangConfig
    COMMAND test -z `gofmt -l ${CMAKE_CURRENT_SOURCE_DIR}`
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Checking format for PluginCommsTwoSixGolangConfig files..."
)
