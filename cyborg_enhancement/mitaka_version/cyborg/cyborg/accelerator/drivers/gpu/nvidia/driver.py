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
Cyborg Intel GPU driver implementation.
"""

import subprocess

from cyborg.accelerator.drivers.gpu.base import GPUDriver
from cyborg.accelerator.drivers.gpu.nvidia import sysinfo


class NVIDIAGPUDriver(GPUDriver):
    """Base class for GPU drivers.

       This is just a virtual GPU drivers interface.
       Vedor should implement their specific drivers.
    """
    VENDOR = "nvidia"

    def __init__(self, *args, **kwargs):
        pass

    def discover(self):
        return sysinfo.gpu_tree()

    def program(self, device_path, image):
        pass
