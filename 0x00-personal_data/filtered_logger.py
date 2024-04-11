#!/usr/bin/env python3
"""Defines the filter_datum function"""
from typing import List
import re
import logging

PII_FIELDS = ("name", "email", "phone", "ssn", "password")

patterns = {
    "extract": lambda x, y: r"(?P<field>{})=[^{}]*".format("|".join(x), y),
    "replace": lambda x: r"\g<field>={}".format(x),
}


def filter_datum(
    fields: List[str],
    redaction: str,
    message: str,
    separator: str,
) -> str:
    """Filters a log string."""
    extract, replace = (patterns["extract"], patterns["replace"])
    return re.sub(extract(fields, separator), replace(redaction), message)


class RedactingFormatter(logging.Formatter):
    """Redacting Formatter class"""

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Formats an incoming log message"""
        message = super(RedactingFormatter, self).format(record)
        res = filter_datum(
            self.fields,
            RedactingFormatter.REDACTION,
            message,
            RedactingFormatter.SEPARATOR,
        )

        return res


def get_logger() -> logging.Logger:
    """Creates a logger"""

    logger = logging.getLogger("user_data")
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(stream_handler)
    return logger
