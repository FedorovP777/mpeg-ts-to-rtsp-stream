import datetime

from dataclasses import _set_new_attribute

from typing import Tuple, Optional, List, Dict


def size_byte_struct(iter: List[Tuple[int, int]]) -> int:
    return sum([size for value, size in iter])


def integers_to_bytes(iter: List[Tuple[int, int]]) -> bytes:
    """Convert integers array to bytes."""
    result = 0
    for value, size in iter:
        result = value ^ (result << size)

    return result.to_bytes(size_byte_struct(iter) // 8, byteorder='big', signed=False)


def byte_struct(cls):
    def wrap(cls):
        _set_new_attribute(cls,
                           '__bytes__',
                           lambda self: integers_to_bytes(self.repr_bytes())
                           )

        _set_new_attribute(cls,
                           '__len__',
                           lambda self: size_byte_struct(self.repr_bytes())
                           )
        return cls

    if cls is None:
        # We're called with parens.
        return wrap

    return wrap(cls)


def utc_time_to_ntp(time_: datetime.datetime) -> Tuple[int, int]:
    """
    Convert utc time to ntp time
    Args:
        time_: datetime.datetime

    Returns: msw and lsw

    """
    lsw = time_.microsecond / 1000000 * 0xffffffff
    msw = time_.timestamp()
    ntp_begin = datetime.datetime(1900, 1, 1)
    utc_begin = datetime.datetime(1970, 1, 1)
    diff = (utc_begin - ntp_begin).total_seconds()
    return int(msw + diff), int(lsw)


assert utc_time_to_ntp(datetime.datetime(2023, 7, 23, 7, 12, 17, 145999, tzinfo=datetime.timezone.utc)) == (3899085137, 627060930)
