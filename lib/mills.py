# -*- coding: utf-8 -*-
import base64
import datetime
import inspect
import logging
import os
import time
from functools import wraps


def fn_timer(function):
    @wraps(function)
    def function_timer(*args, **kwargs):
        t0 = time.time()
        result = function(*args, **kwargs)
        t1 = time.time()
        logging.info("[FUNCOST]: %s: %s seconds" %
                     (function.func_name, str(t1 - t0))
                     )
        return result

    return function_timer


def classinstance2dict(classinstance):
    """
    class instance object to dict
    :param classinstance:
    :return:
    """
    if not classinstance:
        return
    attributes = inspect.getmembers(classinstance, lambda a: not (inspect.isroutine(a)))
    kvlist = [a for a in attributes if not ((a[0].startswith('__') and a[0].endswith('__')) or a[0].startswith('_'))]

    result = {}
    for k, v in kvlist:
        result[k] = v
    return result


def path(*paths):
    """

    :param paths:
    :return:
    """
    MODULE_PATH = os.path.dirname(os.path.realpath(__file__))
    ROOT_PATH = os.path.join(MODULE_PATH, os.path.pardir)
    return os.path.abspath(os.path.join(ROOT_PATH, *paths))


def getCurrenttimestamp():
    """
    get current timestamp in float format
    Returns:

    """
    return time.time()


def timestamp2datetime(ts, tformat="%Y-%m-%d %H:%M:%S"):
    """
    timestamp 2 datetime
    :param timestamp:
    :return:
    """
    ts = ts
    timestamp = datetime.datetime.fromtimestamp(ts).strftime(tformat)
    return timestamp


def get_cur_date(delta=0, format="%Y%m%d"):
    """
    now 20160918, default delata = 0
    :return:
    """
    date = (datetime.date.today() - datetime.timedelta(days=delta)).strftime(format)
    return date


def get_cur_hour_24():
    """
    the hour of today
    :return:
    """
    current_hour = time.strftime('%H', time.localtime(time.time()))
    return current_hour


def is_base64(s):
    """
    check a str is base64 decode or not
    :param s:
    :return:
    """
    try:
        enc = base64.b64decode(s)
        return enc
    except:
        return None


def str2hex(st, return_str=False):
    """

    :param st:
    :return:
    """

    result = ["%02x" % ord(x) for x in st]

    if return_str:
        result = ''.join(result)

    return result


def str2hex2(data, length=16, sep='.'):
    """

    Args:
        data:
        length:
        sep:

    Returns:

    """
    lines = []
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
    for c in xrange(0, len(data), length):
        chars = data[c:c + length]
        hex_str = ' '.join(["%02x" % ord(x) for x in chars])
        printablechars = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or sep) for x in chars])
        lines.append("%08x: %-*s |%s|\n" % (c, length * 3, hex_str, printablechars))

    return ''.join(lines)


if __name__ == "__main__":
    from optparse import OptionParser
    import lib.logger as logger

    logger.generate_special_logger(level=logging.INFO,
                                   logtype="portscan",
                                   curdir=path("./log"))
    parser = OptionParser()

    parser.add_option(
        "--ts2datetime", dest="ts",
        action='store', type='float',
        help="special the fake data filename",
        default=getCurrenttimestamp()
    )

    (options, args) = parser.parse_args()
    print timestamp2datetime(options.ts)
