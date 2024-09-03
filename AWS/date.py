"""Date utils
"""

from datetime import datetime
from typing import Union
import dateparser

RelativeTime = Union[datetime, str, int, float]


def to_date(value: RelativeTime) -> datetime:
    """Convert a relative datetime value to a date time object"""
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value)
    return dateparser.parse(value)
