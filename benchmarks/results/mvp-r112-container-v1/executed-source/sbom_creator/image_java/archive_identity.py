"""Use the same preflight-before-allocation parser for physical config binding."""
from .seekable_layer_index import Layers


def archive_config(path):
    layers = Layers(path)
    try:
        return layers.config_digest, list(layers.mapping)
    finally:
        layers.close()
