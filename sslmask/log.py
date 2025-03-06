import logging


logger = logging.getLogger("sslmask.error")
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(
    fmt=logging.Formatter(fmt="%(asctime)s %(levelname)s: %(message)s")
)
logger.setLevel(level=logging.ERROR)
logger.addHandler(stream_handler)
