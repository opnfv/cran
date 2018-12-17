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
Cyborg GPU driver implementation.
"""
from oslo_log import log as logging

from cyborg.accelerator.drivers.gpu import utils


LOG = logging.getLogger(__name__)

VENDOR_MAPS = {"10de": "nvidia", "102b": "matrox"}


class GPUDriver(object):
    """Base class for GPU drivers.

       This is just a virtual GPU drivers interface.
       Vedor should implement their specific drivers.
    """

    @classmethod
    def create(cls, vendor, *args, **kwargs):
        for sclass in cls.__subclasses__():
            vendor_name = VENDOR_MAPS.get(vendor)
            if vendor_name == sclass.VENDOR:
                return sclass(*args, **kwargs)
        # raise LookupError("Not find the GPU driver for vendor_id %s" % vendor)
        LOG.warn("Not find the GPU driver for vendor_id %s" % vendor)

    def __init__(self, *args, **kwargs):
        pass

    def discover(self):
        raise NotImplementedError()

    def program(self, device_path, image):
        raise NotImplementedError()

    @classmethod
    def discover_vendors(cls):
        return utils.discover_vendors()
