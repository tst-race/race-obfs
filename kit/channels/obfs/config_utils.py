#!/usr/bin/env python3

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

# Python Library Imports
import sys
import logging
import json
import os
import shutil
from typing import Any, Dict, List, Optional, Union


###
# File Utils
###
def read_json(
    json_filename: str,
) -> Any:  # should be Union[Dict[str, Any], List[Any]] but mypy makes that painful
    """
    Purpose:
        Load the range config file into memory as python Dict
    Args:
        json_filename: JSON filename to read
    Raises:
        Exception: if json is invalid
        Exception: if json is not found
    Returns:
        loaded_json: Loaded JSON
    """

    try:
        with open(json_filename, "r") as json_file_onj:
            return json.load(json_file_onj)
    except Exception as load_err:
        logging.error(f"Failed loading {json_filename}")
        raise load_err

def write_json(json_object: Union[Dict[str, Any], List[Any]], json_file: str) -> None:
    """
    Purpose:
        Load Dictionary into JSON File
    Args:
        json_object: Dictionary to be stored in .json format
        json_file: Filename for JSON file to store (including path)
    Returns:
        N/A
    Examples:
        >>> json_file = 'some/path/to/file.json'
        >>> json_object = {
        >>>     'key': 'value'
        >>> }
        >>> write_json_into_file(json_file, json_object)
    """
    logging.info(f"Writing JSON File Into Memory: {json_file}")

    with open(json_file, "w") as file:
        json.dump(json_object, file, sort_keys=True, indent=4, separators=(",", ": "))

def prepare_comms_config_dir(config_dir: str, overwrite: bool) -> None:
    """
    Purpose:
        Prepare the base config dir.
    Args:
        config_dir: Parent directory where all config files and subdirectories are
            stored.
        overwrite: Should we overwrite the config dir if it exists?
    Return:
        N/A
    """

    # Check for existing dir and overwrite
    if os.path.isdir(config_dir):
        if overwrite:
            logging.info(f"{config_dir} exists and overwrite set, removing")
            shutil.rmtree(config_dir)
        else:
            raise Exception(f"{config_dir} exists and overwrite not set, exiting")

    # Make dirs
    os.makedirs(config_dir, exist_ok=True)


###
# Range Config Utils
###
def get_client_details_from_range_config(
    range_config: Dict[str, Any],
    genesis: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Purpose:
        parse clients from a range_config
    Args:
        range_config: range config to parse
        genesis: Genesis value (True or False) on which to filter
            (default is to include all nodes regardless of genesis value)
    Returns:
        clients: clients in the range config
    """

    clients = {}
    for race_node in range_config["range"]["RACE_nodes"]:
        if "client" in race_node.get("type", "").lower():
            if genesis is None or race_node.get("genesis", True) == genesis:
                clients[race_node["name"]] = race_node

    return clients

def validate_range_config(
    range_config: Dict[str, Any],
    allow_no_clients: bool = False,
    allow_non_genesis_servers: bool = False,
) -> None:
    """
    Purpose:
        validate a range_config
    Args:
        range_config: range config to validate
        allow_no_clients: whether or not to allow no clients in range config
        allow_non_genesis_servers: whether or not to allow non-genesis servers in range config
    Raises:
        Exception: if range-config is invalid (for whatever reason)
    Returns:
        N/A
    """

    # validate top level structure
    expected_range_keys = [
        "RACE_nodes",
        "enclaves",
        "services",
    ]
    for range_key in expected_range_keys:
        if range_config["range"].get(range_key, None) is None:
            raise Exception(f"Range Config missing range.{range_key} key")

    # Validate clients/servers exist
    if not get_client_details_from_range_config(range_config) and not allow_no_clients:
        raise Exception("No clients found in range config")
    servers = get_server_details_from_range_config(range_config)
    if not servers:
        raise Exception("No servers found in range config")

    if not allow_non_genesis_servers:
        if any([not node.get("genesis", True) for node in servers.values()]):
            raise Exception("Non-genesis servers found in range config")

    # Validate Enclaves (existance)
    if not range_config["range"].get("enclaves"):
        raise Exception("No enclaves found in range config")

    # TODO, more range config checking

def get_server_details_from_range_config(
    range_config: Dict[str, Any],
    genesis: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Purpose:
        parse servers from a range_config
    Args:
        range_config: range config to parse
        genesis: Genesis value (True or False) on which to filter
            (default is to include all nodes regardless of genesis value)
    Returns:
        servers: servers in the range config
    """

    servers = {}
    for race_node in range_config["range"]["RACE_nodes"]:
        if "server" in race_node.get("type", "").lower():
            if genesis is None or race_node.get("genesis", True) == genesis:
                servers[race_node["name"]] = race_node

    return servers

def get_registry_details_from_range_config(
    range_config: Dict[str, Any],
    genesis: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Purpose:
        parse registries from a range_config
    Args:
        range_config: range config to parse
        genesis: Genesis value (True or False) on which to filter
            (default is to include all nodes regardless of genesis value)
    Returns:
        registries: registries in the range config
    """
    registries = {}
    for race_node in range_config["range"]["RACE_nodes"]:
        if "registry" in race_node.get("type", "").lower():
            if genesis is None or race_node.get("genesis", True) == genesis:
                registries[race_node["name"]] = race_node

    return registries


###
# Network Manager Request Utils
###
def generate_s2s_unicast_network_manager_request_from_range_config(
    range_config: Dict[str, Any], channel_properties_list: List[Dict]
) -> Dict[str, Any]:
    """
    Purpose:
        Generate all server to server requests from the range config based on
        unicast links
    Args:
        range_config: range config to generate against
    Raises:
        Exception: generation fails
    Returns:
        network_manager_request_s2s: requested links based on the range config for S2S connections
    """
    # TODO RACE2-1890 is just adding all channels to all links requests. Needs to be smarter in RACE2-1893.
    channel_list = []
    for channel in channel_properties_list:
        channel_list.append(channel.get("channelGid"))

    network_manager_request_s2s: Dict[str, Any] = {"links": []}

    # Get all servers from range config
    range_config_servers = get_server_details_from_range_config(
        range_config
    )

    # Create unicast from all servers to all servers
    for send_server in range_config_servers:
        for recipient_server in range_config_servers:
            # No requests to send to oneself
            if send_server == recipient_server:
                continue

            network_manager_request_s2s["links"].append(
                {
                    "sender": send_server,
                    "recipients": [recipient_server],
                    "details": {},
                    "groupId": None,
                    "channels": channel_list,
                }
            )

    return network_manager_request_s2s

def generate_c2s_unicast_network_manager_request_from_range_config(
    range_config: Dict[str, Any], channel_properties_list: List[Dict]
) -> Dict[str, Any]:
    """
    Purpose:
        Generate all client to server and server to client requests
        from the range config based on unicast links
    Args:
        range_config: range config to generate against
        transmission_type: type of transmission to prepare network manager request for. Changes the
            which links are possible
    Raises:
        Exception: generation fails
    Returns:
        network_manager_request_c2s: requested links based on the range config for
            C2S/S2C connections
    """
    # TODO RACE2-1890 is just adding all channels to all links requests. Needs to be smarter in RACE2-1893.
    channel_list = []
    for channel in channel_properties_list:
        channel_list.append(channel.get("channelGid"))

    network_manager_request_c2s: Dict[str, Any] = {"links": []}

    # Get clients and servers from range config
    range_config_clients = get_client_details_from_range_config(
        range_config
    )
    range_config_servers = get_server_details_from_range_config(
        range_config
    )

    # Create unicast from all servers to all clients
    for send_server in range_config_servers:
        for recipient_client in range_config_clients:
            network_manager_request_c2s["links"].append(
                {
                    "sender": send_server,
                    "recipients": [recipient_client],
                    "details": {},
                    "groupId": None,
                    "channels": channel_list,
                }
            )

    # Create unicast from all clients to all servers
    for send_client in range_config_clients:
        for recipient_server in range_config_servers:
            network_manager_request_c2s["links"].append(
                {
                    "sender": send_client,
                    "recipients": [recipient_server],
                    "details": {},
                    "groupId": None,
                    "channels": channel_list,
                }
            )

    return network_manager_request_c2s

def generate_s2s_multicast_network_manager_request_from_range_config(
    range_config: Dict[str, Any], channel_properties_list: List[Dict]
) -> Dict[str, Any]:
    """
    Purpose:
        Generate all server to server requests from the range config based on
        multicast links
    Args:
        range_config: range config to generate against
    Raises:
        Exception: generation fails
    Returns:
        network_manager_request_s2s: requested links based on the range config for S2S connections
    """
    # TODO RACE2-1890 is just adding all channels to all links requests. Needs to be smarter in RACE2-1893.
    channel_list = []
    for channel in channel_properties_list:
        channel_list.append(channel.get("channelGid"))

    network_manager_request_s2s: Dict[str, Any] = {"links": []}

    # Get all servers from range config
    range_config_servers = get_server_details_from_range_config(
        range_config
    )

    # Create link request from each server to all servers
    for range_config_server in range_config_servers:

        # Create the recipients and remove the sender from the list
        link_recipients = list(range_config_servers.keys())
        link_recipients.remove(range_config_server)

        network_manager_request_s2s["links"].append(
            {
                "sender": range_config_server,
                "recipients": link_recipients,
                "details": {},
                "groupId": None,
                "channels": channel_list,
            }
        )

    return network_manager_request_s2s

def generate_c2s_multicast_network_manager_request_from_range_config(
    range_config: Dict[str, Any], channel_properties_list: List[Dict]
) -> Dict[str, Any]:
    """
    Purpose:
        Generate all client to server and server to client requests
        from the range config based on unicast links
    Args:
        range_config: range config to generate against
        transmission_type: type of transmision to prepare network manager request for. Changes the
            which links are possible
    Raises:
        Exception: generation fails
    Returns:
        network_manager_request_c2s: requested links based on the range config for
            C2S/S2C connections
    """
    # TODO RACE2-1890 is just adding all channels to all links requests. Needs to be smarter in RACE2-1893.
    channel_list = []
    for channel in channel_properties_list:
        channel_list.append(channel.get("channelGid"))

    network_manager_request_c2s: Dict[str, Any] = {"links": []}

    # Get clients and servers from range config
    range_config_clients = get_client_details_from_range_config(
        range_config
    )
    range_config_servers = get_server_details_from_range_config(
        range_config
    )

    # Create link request from each client to all servers
    for range_config_client in range_config_clients:
        network_manager_request_c2s["links"].append(
            {
                "sender": range_config_client,
                "recipients": list(range_config_servers.keys()),
                "details": {},
                "groupId": None,
                "channels": channel_list,
            }
        )

    # Create link request from each server to all clients
    for range_config_server in range_config_servers:
        network_manager_request_c2s["links"].append(
            {
                "sender": range_config_server,
                "recipients": list(range_config_clients.keys()),
                "details": {},
                "groupId": None,
                "channels": channel_list,
            }
        )

    return network_manager_request_c2s

def generate_network_manager_request_from_range_config(
    range_config: Dict[str, Any],
    channel_properties_list: List[Dict[str, Any]],
    transmission_type: str,
    link_type: str,
) -> Dict[str, Any]:
    """
    Purpose:
        If no network manager request is passed in, generate one for indirect links.

        Transmission Type:
            - Unicast: one sender/recipient
            - Multicast: multi senders/recipients

        Link Type:
            - Direct: cannot include client<->server links.
            - Indirect: can include client<->server and server<->server links.

        The assumption that if there is no Network Manager request, then the Comms plugin should
        create all possible links given the range config
    Args:
        range_config: range config to generate against
        transmission_type: type of transmission to prepare network manager request for. Changes the
            which links are possible
        link_type: type of link to prepare network manager request for. Changes the structure
            of the resulting links.
    Raises:
        Exception: generation fails
    Returns:
        network_manager_request: requested links based on the range config
    """

    # Verify Params
    valid_link_types = ("direct", "indirect")
    if link_type not in valid_link_types:
        raise Exception(f"{link_type} is not a valid link_type ({valid_link_types})")
    valid_transmission_types = ("unicast", "multicast")
    if transmission_type not in valid_transmission_types:
        raise Exception(
            f"{transmission_type} is not a valid transmission_type "
            f"({valid_transmission_types})"
        )

    network_manager_request = {}

    # Add S2S Requests
    if transmission_type == "unicast":
        network_manager_request = generate_s2s_unicast_network_manager_request_from_range_config(
            range_config, channel_properties_list
        )

        # Add C2S Requests (only when not direct)
        if link_type != "direct":
            c2s_unicast = generate_c2s_unicast_network_manager_request_from_range_config(
                range_config, channel_properties_list
            )

            if not network_manager_request:
                network_manager_request = c2s_unicast
            elif c2s_unicast:
                network_manager_request["links"].extend(c2s_unicast["links"])

    elif transmission_type == "multicast":
        network_manager_request = generate_s2s_multicast_network_manager_request_from_range_config(
            range_config, channel_properties_list
        )

        # Add C2S Requests (only when not direct)
        if link_type != "direct":
            c2s_multicast = generate_c2s_multicast_network_manager_request_from_range_config(
                range_config, channel_properties_list
            )

            if not network_manager_request:
                network_manager_request = c2s_multicast
            elif c2s_multicast:
                network_manager_request["links"].extend(c2s_multicast["links"])

    return network_manager_request

def validate_network_manager_request(
    network_manager_request: Dict[str, Any],
    range_config: Dict[str, Any],
) -> None:
    """
    Purpose:
        validate a network manager request of links

        check that the request isn't wildly inaccurate to the
        range config. e.g. network manager should not have requested links
        for nodes that don't exist.
    Args:
        network_manager_request: requested links to validate
        range_config: range config to validate against
    Raises:
        Exception: if network_manager_request is invalid (for whatever reason)
    Returns:
        N/A
    """

    # validate top level structure
    if not network_manager_request.get("links"):
        raise Exception(f"Network Manager Link Request missing links key")

    # Parse out race_node details
    range_config_race_nodes = []
    range_config_clients = get_client_details_from_range_config(
        range_config
    )
    range_config_race_nodes.extend(list(range_config_clients.keys()))
    range_config_registries = get_registry_details_from_range_config(
        range_config=range_config,
    )
    range_config_race_nodes.extend(list(range_config_registries.keys()))
    range_config_servers = get_server_details_from_range_config(
        range_config
    )
    range_config_race_nodes.extend(list(range_config_servers.keys()))

    # Validate the links are for expected clients
    invalid_send_nodes_in_request = set()
    invalid_recipient_nodes_in_request = set()
    for requested_link in network_manager_request["links"]:

        # Every link needs a sender and recipient
        if not requested_link.get("sender"):
            raise Exception(f"Requested Link ({requested_link}) has no senders")
        if not requested_link.get("recipients"):
            raise Exception(f"Requested Link ({requested_link}) has no recipients")

        # Validate sender/recipients in range-config
        if requested_link["sender"] not in range_config_race_nodes:
            invalid_send_nodes_in_request.add(requested_link["sender"])
        for recipient in requested_link["recipients"]:
            if recipient not in range_config_race_nodes:
                invalid_recipient_nodes_in_request.add(recipient)

    if invalid_send_nodes_in_request:
        raise Exception(
            "Invalid nodes found in Network Manager link request senders: "
            f"{', '.join(invalid_send_nodes_in_request)}"
        )

    if invalid_recipient_nodes_in_request:
        raise Exception(
            "Invalid nodes found in Network Manager link request recipients: "
            f"{', '.join(invalid_recipient_nodes_in_request)}"
        )



###
# Generate Link Functions
###


def generate_link_properties_dict(
    link_type: str,
    transmission_type: str,
    reliability: bool,
    exp_latency_ms: str,
    exp_bandwidth_bps: str,
    exp_variance_pct: float = 0.1,
    supported_hints: List[str] = [],
) -> Dict[str, Any]:
    """
    Purpose:
        Generate RACE Link Properties Dict from values.

        Expected will be passed in with a variance to build best/worst/expected
    Args:
        link_type: ("send" or "receive") indicating the type of link
        transmission_type: ("unicast" or "multicast") indicating the
            transmission type
        reliability: indicates if the link is reliable to Network Manager
        exp_latency_ms: expected latency using the link in milliseconds
        exp_bandwidth_bps: expected bandwidth using the link in bytes
        exp_variance_pct: expected variance (as a percentage between 0.0 and 1.0) between
            best and worst case scenarios.
        supported_hints: all supported hints for the link
    Return:
        link_properties: Dict containing link properties
    """

    return {
        "type": link_type,
        "reliable": reliability,
        transmission_type: True,  # set the transmission type key
        "supported_hints": supported_hints,
        "expected": {
            link_type: {
                "latency_ms": exp_latency_ms,
                "bandwidth_bps": exp_bandwidth_bps,
            }
        },
        "best": {
            link_type: {
                "latency_ms": int(exp_latency_ms * (1 - exp_variance_pct)),
                "bandwidth_bps": int(exp_bandwidth_bps * (1 + exp_variance_pct)),
            }
        },
        "worst": {
            link_type: {
                "latency_ms": int(exp_latency_ms * (1 + exp_variance_pct)),
                "bandwidth_bps": int(exp_bandwidth_bps * (1 - exp_variance_pct)),
            }
        },
    }