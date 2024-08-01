#!/usr/bin/env python3
"""
Module to filter logs and handle sensitive data.
"""
import os
import re
import logging
import mysql.connector
from typing import List

# Define patterns for extracting and replacing PII in logs
patterns = {
    'extract': lambda fields, sep: r'(?P<field>{})=[^{}]*'.format(
        '|'.join(fields), sep),
    'replace': lambda redaction: r'\g<field>={}'.format(redaction),
}

# List of fields considered as Personally Identifiable Information (PII)
PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str) -> str:
    """
    Redacts sensitive information from a log message.

    Args:
        fields (List[str]): Fields to redact.
        redaction (str): The replacement text for the redacted fields.
        message (str): The original log message.
        separator (str): The separator used in the log message.

    Returns:
        str: The log message with redacted fields.
    """
    extract_pattern = patterns["extract"](fields, separator)
    replace_pattern = patterns["replace"](redaction)
    return re.sub(extract_pattern, replace_pattern, message)


def get_logger() -> logging.Logger:
    """
    Creates and configures a logger for user data logs.

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger("user_data")
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Establishes a connection to the database using environment variables.

    Returns:
        mysql.connector.connection.MySQLConnection: Database connection object.
    """
    db_config = {
        'host': os.getenv("PERSONAL_DATA_DB_HOST", "localhost"),
        'database': os.getenv("PERSONAL_DATA_DB_NAME", ""),
        'user': os.getenv("PERSONAL_DATA_DB_USERNAME", "root"),
        'password': os.getenv("PERSONAL_DATA_DB_PASSWORD", ""),
        'port': 3306
    }
    return mysql.connector.connect(**db_config)


def main():
    """
    Fetches and logs user records from the database.
    """
    fields = "name,email,phone,ssn,password,ip,last_login,user_agent"
    columns = fields.split(',')
    query = "SELECT {} FROM users;".format(fields)
    logger = get_logger()
    connection = get_db()
    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()
        for row in rows:
            record = '; '.join(['{}={}'.format(col, val) for col, val in zip(
                columns, row)])
            log_record = logging.LogRecord("user_data", logging.INFO, None,
                                           None, record, None, None)
            logger.handle(log_record)


class RedactingFormatter(logging.Formatter):
    """
    Formatter that redacts sensitive information from log messages.
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Initializes the formatter with fields to redact.

        Args:
            fields (List[str]): Fields to be redacted in log messages.
        """
        super().__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Formats the log record and redacts sensitive information.

        Args:
            record (logging.LogRecord): The log record to format and redact.

        Returns:
            str: The formatted log record with redacted information.
        """
        msg = super().format(record)
        return filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)


if __name__ == "__main__":
    main()
