from cyborg.accelerator.drivers.gpu.nvidia.driver import NVIDIAGPUDriver
import os
import glob

from oslo_log import log as logging


__import__('pkg_resources').declare_namespace(__name__)
__import__(".".join([__package__, 'base']))


LOG = logging.getLogger(__name__)


def load_gpu_vendor_driver():
    files = glob.glob(os.path.join(os.path.dirname(__file__), "*/driver*"))
    modules = set(map(lambda s: ".".join(s.rsplit(".")[0].rsplit("/", 2)[-2:]),
                      files))
    for m in modules:
        try:
            __import__(".".join([__package__, m]))
            LOG.debug("Successfully loaded GPU vendor driver: %s." % m)
        except ImportError as e:
            LOG.error("Failed to load GPU vendor driver: %s. Details: %s"
                      % (m, e))


load_gpu_vendor_driver()
