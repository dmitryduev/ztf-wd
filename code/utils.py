import os
import inspect
import json
import numpy as np
import datetime
import pytz


def utc_now():
    return datetime.datetime.now(pytz.utc)


def jd(_t):
    """
    Calculate Julian Date
    """
    assert isinstance(_t, datetime.datetime), 'function argument must be a datetime.datetime instance'

    a = np.floor((14 - _t.month) / 12)
    y = _t.year + 4800 - a
    m = _t.month + 12 * a - 3

    jdn = _t.day + np.floor((153 * m + 2) / 5.) + 365 * y + np.floor(y / 4.) - np.floor(y / 100.) + np.floor(
        y / 400.) - 32045

    _jd = jdn + (_t.hour - 12.) / 24. + _t.minute / 1440. + _t.second / 86400. + _t.microsecond / 86400000000.

    return _jd


def mjd(_t):
    """
    Calculate Modified Julian Date
    """
    assert isinstance(_t, datetime.datetime), 'function argument must be a datetime.datetime instance'
    _jd = jd(_t)
    _mjd = _jd - 2400000.5
    return _mjd


def get_config(_config_file='/app/config.json'):
    """
        load config data in json format
    """
    try:
        ''' script absolute location '''
        abs_path = os.path.dirname(inspect.getfile(inspect.currentframe()))

        if _config_file[0] not in ('/', '~'):
            if os.path.isfile(os.path.join(abs_path, _config_file)):
                config_path = os.path.join(abs_path, _config_file)
            else:
                raise IOError('Failed to find config file')
        else:
            if os.path.isfile(_config_file):
                config_path = _config_file
            else:
                raise IOError('Failed to find config file')

        with open(config_path) as cjson:
            config_data = json.load(cjson)
            # config must not be empty:
            if len(config_data) > 0:
                return config_data
            else:
                raise Exception('Failed to load config file')

    except Exception as _e:
        print(_e)
        raise Exception('Failed to read in the config file')