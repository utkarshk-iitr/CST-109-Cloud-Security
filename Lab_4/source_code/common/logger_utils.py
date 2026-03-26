import logging
import os
from common.config import LOG_DIR

LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

def get_logger(name, filename, level=logging.INFO):
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(level)
    logger.propagate = False

    os.makedirs(LOG_DIR, exist_ok=True)

    file_handler = logging.FileHandler(os.path.join(LOG_DIR, filename))
    stream_handler = logging.StreamHandler()

    formatter = logging.Formatter(LOG_FORMAT)
    file_handler.setFormatter(formatter)
    stream_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

    return logger
