# VolWeb channel layer patch — mounts over the baked-in settings.py
# Imports everything from the original backend.settings, then overrides
# CHANNEL_LAYERS so Django Channels uses a password-authenticated Redis URL
# instead of the bare (host, port) tuple that causes AuthenticationError.

from backend.settings import *  # noqa: F401,F403
import os

_redis_password = os.environ.get("REDIS_PASSWORD", "")
_broker_host = os.environ.get("BROKER_HOST", "redis")
_broker_port = os.environ.get("BROKER_PORT", "6379")

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [
                f"redis://:{_redis_password}@{_broker_host}:{_broker_port}/0"
            ],
        },
    },
}
