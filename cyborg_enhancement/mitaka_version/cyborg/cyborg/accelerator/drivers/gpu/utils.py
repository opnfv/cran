# Copyright 2018 Lenovo, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


"""
Utils for GPU driver.
"""

import re
import subprocess


GPU_FLAGS = ["VGA compatible controller", "3D controller"]
GPU_INFO_PATTERN = re.compile("(?P<devices>[0-9]{2}:[0-9]{2}\.[0-9]) (?P"
                              "<name>.*) \[.* [\[](?P<vendor_id>[0-9a-fA-F]{4})"
                              ":(?P<product_id>[0-9a-fA-F]{4})] .*")


def discover_vendors():
    cmd = "sudo lspci -nnn | grep -E '%s'"
    cmd = cmd % "|".join(GPU_FLAGS)
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    p.wait()
    gpus = p.stdout.readlines()
    vendors = set()
    for gpu in gpus:
        m = GPU_INFO_PATTERN.match(gpu)
        if m:
            vendor_id = m.groupdict().get("vendor_id")
            vendors.add(vendor_id)
    return vendors


def discover_gpus(vender_id=None):
    cmd = "sudo lspci -nnn | grep -E '%s'"
    cmd = cmd % "|".join(GPU_FLAGS)
    if vender_id:
        cmd = cmd + "| grep " + vender_id
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    p.wait()
    gpus = p.stdout.readlines()
    gpu_list = []
    for gpu in gpus:
        m = GPU_INFO_PATTERN.match(gpu)
        if m:
            gpu_dict = m.groupdict()
            gpu_dict["function"] = "GPU"
            gpu_dict["devices"] = _match_nova_addr(gpu_dict["devices"])
            gpu_dict["assignable"] = True
            gpu_list.append(gpu_dict)
    return gpu_list


def _match_nova_addr(devices):
    addr = '0000:'+devices.replace(".", ":")
    return addr
