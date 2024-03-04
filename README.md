# **Resilient Anonymous Communication for Everyone (RACE) Obfs Guide**

## **Table of Contents**
- [**Introduction**](#introduction)
  * [**Design Goals**](#design-goals)
  * [**Security Considerations**](#security-considerations)
- [**Scope**](#scope)
  * [**Audience**](#audience)
  * [**Environment**](#environment)
  * [**License**](#license)
  * [**Additional Reading**](#additional-reading)
- [**Implementation Overview**](#implementation-overview)
- [**Implementation Organization**](#implementation-organization)
  * [source](#source)
  * [config-utils](#config-utils)
- [**How To Build**](#how-to-build)
- [**How To Run**](#how-to-run)

<br></br>

## **Introduction**
This plugin provides a RACE Comms Plugin interface for the look-like-nothing [Obfs](https://github.com/RACECAR-GU/obfsX) network protocol.
</br>

### **Design Goals**
Provide high-bandwidth low-latency direct network communications between RACE servers.

### **Security Considerations**
Obfs is designed to be difficult to positively classify or filter from other various network protocols. Obfs is not necessarily resilient to network environments with restrictive protocol whitelisting.

This plugin is a research prototype and has not been the subject of an independent security audit or extensive external testing.

<br></br>

## **Scope**
This developer guide covers the  development model, building artifacts, running, and troubleshooting.  It is structured this way to first provide context, associate attributes/features with source files, then guide a developer through the build process.  

</br>

### **Audience**
Technical/developer audience.

### **Environment**
Works on x86 and arm64 hosts, only used between RACE servers and therefore it is only built for Linux, not Android.

### **License**
Licensed under the APACHE 2.0 license, see LICENSE file for more information.

### **Additional Reading**
* [RACE Quickstart Guide](https://github.com/tst-race/race-quickstart/blob/main/README.md)

* [What is RACE: The Longer Story](https://github.com/tst-race/race-docs/blob/main/what-is-race.md)

* [Developer Documentation](https://github.com/tst-race/race-docs/blob/main/RACE%20developer%20guide.md)

* [RIB Documentation](https://github.com/tst-race/race-in-the-box/tree/2.6.0/documentation)

<br></br>

## **Implementation Overview**


<br></br>

## **Implementation Organization**
### source
Contains source for RACE API wrappers and Go imports of internal Obfs implementations.

### config-utils
Contains standalone implementation of Obfs key generation algorithm for pregenerating configurations.

<br></br>

## **How To Build**
Build is done inside a race-sdk docker container, run:
```
./build_artifacts_in_docker_image.sh
```
This will produce a `kit` directory that can be used in a RACE deployment. Note that it will only produce artifacts for the host architecture.

</br>

## **How To Run**

Include in a RACE deployment for server-to-server communications by adding the following arguments to a `rib deployment create` command:
```
--comms-channel=obfs --comms-kit=<kit source for obfs>
```

</br>
