import argparse
import datetime
import inspect
import logging
import os
import sys
import time
import pytz
import traceback
import pymongo
from astropy.time import Time
import json
from penquins import Kowalski
import numpy as np
import pandas as pd
# import unittest

import matplotlib
# Force matplotlib to not use any Xwindows backend.
matplotlib.use('Agg')
from PIL import Image
import io
import gzip
from astropy.io import fits
from matplotlib.colors import LogNorm
import matplotlib.pyplot as plt

# with open('/app/crontest.txt', 'w') as f:
#     f.write(str(datetime.datetime.utcnow()))

# load secrets:
# with open('/Users/dmitryduev/_caltech/python/ztf-wd/secrets.json') as sjson:
with open('/app/secrets.json') as sjson:
    secrets = json.load(sjson)


# class TestCrossMatch(unittest.TestCase):
#
#     def test_wrong_types_raise_exception(self):
#         self.cases = ['string', 1.5]
#
#         for c in self.cases:
#             with self.subTest(case=c):
#
#                 self.assertRaises(TypeError, cross_match, c, msg=f'TypeError not raised on: {c}')


def utc_now():
    return datetime.datetime.now(pytz.utc)


def time_stamps():
    """

    :return: local time, UTC time
    """
    return datetime.datetime.now().strftime('%Y%m%d_%H:%M:%S'), \
           datetime.datetime.utcnow().strftime('%Y%m%d_%H:%M:%S')


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]


def make_dataframe(packet):
    df = pd.DataFrame(packet['candidate'], index=[0])  # the current alert
    df_prv = pd.DataFrame(packet['prv_candidates'])  # obtaining all previous alerts at this location
    return pd.concat([df, df_prv], ignore_index=True)  # we put the current alert and previous ones in the same table


class WhiteDwarf(object):

    def __init__(self, config_file: str):
        try:
            ''' load config data '''
            self.config = self.get_config(_config_file=config_file)

            ''' set up logging at init '''
            self.logger, self.logger_utc_date = self.set_up_logging(_name='archive', _mode='a')

            # make dirs if necessary:
            for _pp in ('app', 'alerts', 'tmp', 'logs'):
                _path = self.config['path']['path_{:s}'.format(_pp)]
                if not os.path.exists(_path):
                    os.makedirs(_path)
                    self.logger.debug('Created {:s}'.format(_path))

            ''' init connection to Kowalski '''
            self.kowalski = Kowalski(username=secrets['kowalski']['user'],
                                     password=secrets['kowalski']['password'])
            # host='localhost', port=8082, protocol='http'

            ''' init db if necessary '''
            self.init_db()

            ''' connect to db: '''
            self.db = None
            # will exit if this fails
            self.connect_to_db()

        except Exception as e:
            print(e)
            traceback.print_exc()
            sys.exit()

    @staticmethod
    def get_config(_config_file):
        """
            Load config JSON file
        """
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

    def set_up_logging(self, _name='ztf_wd', _mode='w'):
        """ Set up logging

            :param _name:
            :param _level: DEBUG, INFO, etc.
            :param _mode: overwrite log-file or append: w or a
            :return: logger instance
            """
        # 'debug', 'info', 'warning', 'error', or 'critical'
        if self.config['misc']['logging_level'] == 'debug':
            _level = logging.DEBUG
        elif self.config['misc']['logging_level'] == 'info':
            _level = logging.INFO
        elif self.config['misc']['logging_level'] == 'warning':
            _level = logging.WARNING
        elif self.config['misc']['logging_level'] == 'error':
            _level = logging.ERROR
        elif self.config['misc']['logging_level'] == 'critical':
            _level = logging.CRITICAL
        else:
            raise ValueError('Config file error: logging level must be ' +
                             '\'debug\', \'info\', \'warning\', \'error\', or \'critical\'')

        # get path to logs from config:
        _path = self.config['path']['path_logs']

        if not os.path.exists(_path):
            os.makedirs(_path)
        utc_now = datetime.datetime.utcnow()

        # http://www.blog.pythonlibrary.org/2012/08/02/python-101-an-intro-to-logging/
        _logger = logging.getLogger(_name)

        _logger.setLevel(_level)
        # create the logging file handler
        fh = logging.FileHandler(os.path.join(_path, '{:s}.{:s}.log'.format(_name, utc_now.strftime('%Y%m%d'))),
                                 mode=_mode)
        logging.Formatter.converter = time.gmtime

        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        # formatter = logging.Formatter('%(asctime)s %(message)s')
        fh.setFormatter(formatter)

        # add handler to logger object
        _logger.addHandler(fh)

        return _logger, utc_now.strftime('%Y%m%d')

    def shut_down_logger(self):
        """
            Prevent writing to multiple log-files after 'manual rollover'
        :return:
        """
        handlers = self.logger.handlers[:]
        for handler in handlers:
            handler.close()
            self.logger.removeHandler(handler)

    def check_logging(self):
        """
            Check if a new log file needs to be started and start it if necessary
        """
        if datetime.datetime.utcnow().strftime('%Y%m%d') != self.logger_utc_date:
            # reset
            self.shut_down_logger()
            self.logger, self.logger_utc_date = self.set_up_logging(_name='ztf_wd', _mode='a')

    def init_db(self):
        """
            Initialize db if new Mongo instance
        :return:
        """
        _client = pymongo.MongoClient(username=self.config['database']['admin'],
                                      password=self.config['database']['admin_pwd'],
                                      host=self.config['database']['host'],
                                      port=self.config['database']['port'])
        # _id: db_name.user_name
        user_ids = [_u['_id'] for _u in _client.admin.system.users.find({}, {'_id': 1})]

        db_name = self.config['database']['db']
        username = self.config['database']['user']

        # print(f'{db_name}.{username}')
        # print(user_ids)

        if f'{db_name}.{username}' not in user_ids:
            _client[db_name].command('createUser', self.config['database']['user'],
                                     pwd=self.config['database']['pwd'], roles=['readWrite'])
            self.logger.info('Successfully initialized db')

    def connect_to_db(self):
        """
            Connect to MongoDB-powered database
        :return:
        """
        _config = self.config
        try:
            if self.logger is not None:
                self.logger.debug('Connecting to the database at {:s}:{:d}'.
                                  format(_config['database']['host'], _config['database']['port']))
            _client = pymongo.MongoClient(host=_config['database']['host'], port=_config['database']['port'])
            # grab main database:
            _db = _client[_config['database']['db']]

        except Exception as _e:
            if self.logger is not None:
                self.logger.error(_e)
                self.logger.error('Failed to connect to the database at {:s}:{:d}'.
                                  format(_config['database']['host'], _config['database']['port']))
            # raise error
            raise ConnectionRefusedError
        try:
            # authenticate
            _db.authenticate(_config['database']['user'], _config['database']['pwd'])
            if self.logger is not None:
                self.logger.debug('Successfully authenticated with the database at {:s}:{:d}'.
                                  format(_config['database']['host'], _config['database']['port']))
        except Exception as _e:
            if self.logger is not None:
                self.logger.error(_e)
                self.logger.error('Authentication failed for the database at {:s}:{:d}'.
                                  format(_config['database']['host'], _config['database']['port']))
            raise ConnectionRefusedError

        if self.logger is not None:
            self.logger.debug('Successfully connected to database at {:s}:{:d}'.
                              format(_config['database']['host'], _config['database']['port']))

        # (re)define self.db
        self.db = dict()
        self.db['client'] = _client
        self.db['db'] = _db

    # @timeout(seconds_before_timeout=120)
    def disconnect_from_db(self):
        """
            Disconnect from MongoDB database.
        :return:
        """
        self.logger.debug('Disconnecting from the database.')
        if self.db is not None:
            try:
                self.db['client'].close()
                self.logger.debug('Successfully disconnected from the database.')
            except Exception as e:
                self.logger.error('Failed to disconnect from the database.')
                self.logger.error(e)
            finally:
                # reset
                self.db = None
        else:
            self.logger.debug('No connection found.')

    # @timeout(seconds_before_timeout=120)
    def check_db_connection(self):
        """
            Check if DB connection is alive/established.
        :return: True if connection is OK
        """
        self.logger.debug('Checking database connection.')
        if self.db is None:
            try:
                self.connect_to_db()
            except Exception as e:
                self.logger.error('Lost database connection.')
                self.logger.error(e)
                return False
        else:
            try:
                # force connection on a request as the connect=True parameter of MongoClient seems
                # to be useless here
                self.db['client'].server_info()
            except pymongo.errors.ServerSelectionTimeoutError as e:
                self.logger.error('Lost database connection.')
                self.logger.error(e)
                return False

        return True

    def insert_db_entry(self, _collection=None, _db_entry=None):
        """
            Insert a document _doc to collection _collection in DB.
            It is monitored for timeout in case DB connection hangs for some reason
        :param _collection:
        :param _db_entry:
        :return:
        """
        assert _collection is not None, 'Must specify collection'
        assert _db_entry is not None, 'Must specify document'
        try:
            self.db['db'][_collection].insert_one(_db_entry)
        except Exception as _e:
            self.logger.info('Error inserting {:s} into {:s}'.format(str(_db_entry['_id']), _collection))
            traceback.print_exc()
            self.logger.error(_e)

    def insert_multiple_db_entries(self, _collection=None, _db_entries=None):
        """
            Insert a document _doc to collection _collection in DB.
            It is monitored for timeout in case DB connection hangs for some reason
        :param _db:
        :param _collection:
        :param _db_entries:
        :return:
        """
        assert _collection is not None, 'Must specify collection'
        assert _db_entries is not None, 'Must specify documents'
        try:
            # ordered=False ensures that every insert operation will be attempted
            # so that if, e.g., a document already exists, it will be simply skipped
            self.db['db'][_collection].insert_many(_db_entries, ordered=False)
        except pymongo.errors.BulkWriteError as bwe:
            self.logger.info(bwe.details)
        except Exception as _e:
            traceback.print_exc()
            self.logger.error(_e)

    def replace_db_entry(self, _collection=None, _filter=None, _db_entry=None):
        """
            Insert a document _doc to collection _collection in DB.
            It is monitored for timeout in case DB connection hangs for some reason
        :param _collection:
        :param _filter:
        :param _db_entry:
        :return:
        """
        assert _collection is not None, 'Must specify collection'
        assert _db_entry is not None, 'Must specify document'
        try:
            self.db['db'][_collection].replace_one(_filter, _db_entry, upsert=True)
        except Exception as _e:
            self.logger.info('Error replacing {:s} in {:s}'.format(str(_db_entry['_id']), _collection))
            traceback.print_exc()
            self.logger.error(_e)

    def cross_match(self, _jd_start, _jd_end, _stars: dict, _fov_size_ref_arcsec=2, retries=3) -> dict:

        for ir in range(retries):
            try:
                self.logger.debug(f'Querying Kowalski, attempt {ir+1}')
                # query Kowalski for Gaia stars:
                # if False:
                q = {"query_type": "cone_search",
                     "object_coordinates": {"radec": str(_stars),
                                            "cone_search_radius": str(_fov_size_ref_arcsec),
                                            "cone_search_unit": "arcsec"},
                     "catalogs": {"ZTF_alerts": {"filter": {"candidate.jd": {"$gt": _jd_start,
                                                                             "$lt": _jd_end}},
                                                 "projection": {}}
                                  }
                     }
                # {"candidate.jd": {"$gt": _jd, "$lt": _jd + 1}}
                # {"_id": 1, "objectId": 1,
                #                                                             "candid": 1,
                #                                                             "candidate.jd": 1,
                #                                                             "candidate.programid": 1,
                #                                                             "candidate.rb": 1,
                #                                                             "candidate.magpsf": 1,
                #                                                             "candidate.sigmapsf": 1}
                # ,
                #                               "Gaia_DR2_WD": {"filter": {},
                #                                               "projection": {"_id": 1, "coordinates": 0}}
                # print(q)
                r = self.kowalski.query(query=q, timeout=20)
                # print(r)

                matches = r['result']['ZTF_alerts']

                # only return non-empty matches:
                non_empty_matches = {m: v for m, v in matches.items() if v is not None}

                return non_empty_matches

            except Exception as _e:
                self.logger.error(_e)
                continue

        return {}

    def get_doc_by_id(self, _coll: str, _ids: list, retries=3) -> dict:

        for ir in range(retries):
            try:
                self.logger.debug(f'Querying Kowalski, attempt {ir+1}')
                q = {"query_type": "general_search",
                     "query": f"db['{_coll}'].find({{'_id': {{'$in': {_ids}}}}})"
                     }
                # print(q)
                r = self.kowalski.query(query=q, timeout=10)
                # print(r)
                result = r['result']['query_result']

                # convert to dict id -> result
                matches = {obj['_id']: obj for obj in result}

                return matches

            except Exception as _e:
                self.logger.error(_e)
                continue

        return {}

    def dump_lightcurve(self, alert, days_ago=True):
        path_out = os.path.join(self.config['path']['path_alerts'], alert['_id'])

        if not os.path.exists(path_out):
            os.makedirs(path_out)

        dflc = make_dataframe(alert)

        filter_color = {1: 'green', 2: 'red', 3: 'pink'}
        if days_ago:
            now = Time.now().jd
            t = dflc.jd - now
            xlabel = 'Days Ago'
        else:
            t = dflc.jd
            xlabel = 'Time (JD)'

        plt.close('all')
        fig = plt.figure()
        ax = fig.add_subplot(111)
        for fid, color in filter_color.items():
            # plot detections in this filter:
            w = (dflc.fid == fid) & ~dflc.magpsf.isnull()
            if np.sum(w):
                ax.errorbar(t[w], dflc.loc[w, 'magpsf'], dflc.loc[w, 'sigmapsf'],
                            fmt='.', color=color)
            wnodet = (dflc.fid == fid) & dflc.magpsf.isnull() & (dflc.diffmaglim > 0)
            if np.sum(wnodet):
                ax.scatter(t[wnodet], dflc.loc[wnodet, 'diffmaglim'],
                           marker='v', color=color, alpha=0.25)

        plt.gca().invert_yaxis()
        ax.set_xlabel(xlabel)
        ax.set_ylabel('Magnitude')

        plt.savefig(os.path.join(path_out, 'lightcurve.jpg'), dpi=150)

    def dump_cutout(self, alert, save_fits=False):
        path_out = os.path.join(self.config['path']['path_alerts'], alert['_id'])

        if not os.path.exists(path_out):
            os.makedirs(path_out)

        for tag in ('science', 'template', 'difference'):

            data = alert[f'cutout{tag.capitalize()}']['stampData']

            tmp = io.BytesIO()
            tmp.write(data)
            tmp.seek(0)

            # new format? try to decompress loss-less fits:
            try:
                decompressed_file = gzip.GzipFile(fileobj=tmp, mode='rb')

                with fits.open(decompressed_file) as dff:
                    if save_fits:
                        dff.writeto(os.path.join(path_out, f'{tag}.fits'), overwrite=True)
                    # print(dff[0].data)

                    img = dff[0].data

                    plt.close('all')
                    fig = plt.figure()
                    fig.set_size_inches(4, 4, forward=False)
                    ax = plt.Axes(fig, [0., 0., 1., 1.])
                    ax.set_axis_off()
                    fig.add_axes(ax)

                    # remove nans:
                    img = np.array(img)
                    img = np.nan_to_num(img)

                    if tag != 'difference':
                        # img += np.min(img)
                        img[img <= 0] = np.median(img)
                        plt.imshow(img, cmap='gray', norm=LogNorm(), origin='lower')
                    else:
                        plt.imshow(img, cmap='gray', origin='lower')
                    plt.savefig(os.path.join(path_out, f'{tag}.jpg'), dpi=50)

            # failed? try old jpg format
            except Exception as _e:
                traceback.print_exc()
                self.logger.error(str(_e))
                try:
                    tmp.seek(0)
                    Image.open(tmp).save(os.path.join(path_out, f'{tag}.jpg'))
                finally:
                    self.logger.error(f'Failed to save stamp: {alert[_id]} {tag}')

    def get_ps1_image(self, alert):
        """

        :param alert:
        :return:
        """
        # TODO: get PanSTARRS image
        pass

    def run(self, _all=False):
        # compute current UTC. the script is run everyday at 19:00 UTC (~noon in LA)
        utc_date = datetime.datetime.utcnow()
        utc_date = datetime.datetime(utc_date.year, utc_date.month, utc_date.day)

        # convert to jd
        jd_date = Time(utc_date).jd
        self.logger.info('Starting cycle: {} {}'.format(str(utc_date), str(jd_date)))

        if not _all:
            # grab last night only
            jd_start = jd_date
            jd_end = jd_date + 1
        else:
            # grab everything:
            utc_date_survey_start = datetime.datetime(2017, 9, 1)
            jd_date_survey_start = Time(utc_date_survey_start).jd
            jd_start = jd_date_survey_start
            jd_end = jd_date + 1

        # with open('/Users/dmitryduev/_caltech/python/ztf-wd/code/wds.20180811.json') as wdjson:
        with open(self.config['path']['path_wd_db']) as wdjson:
            wds = json.load(wdjson)['query_result']

        total_detected = 0

        matches_to_ingest = []

        # for batch_size run a cross match with ZTF_alerts for current UTC
        for ic, chunk in enumerate(chunks(wds, 1000)):
            self.logger.info(f'Chunk #{ic}')
            # print(chunk[0]['_id'])

            # {name: (ra, dec)}
            stars = {c['_id']: (c['ra'], c['dec']) for c in chunk}
            # print(stars)

            # run cone search on the batch
            matches = self.cross_match(_jd_start=jd_start, _jd_end=jd_end,
                                       _stars=stars, _fov_size_ref_arcsec=2, retries=3)

            self.logger.debug(list(matches.keys()))

            total_detected += len(matches)
            self.logger.info(f'total detected so far: {total_detected}')

            if len(matches) > 0:
                # get full WD info for matched objects:
                wds = self.get_doc_by_id(_coll='Gaia_DR2_WD', _ids=list(map(int, matches.keys())), retries=3)

                # append to corresponding matches
                self.logger.debug(list(matches.keys()))
                for match in matches.keys():
                    for alert in matches[match]:
                        alert['xmatch'] = dict()
                        alert['xmatch']['nearest_within_5_arcsec'] = {'Gaia_DR2_WD': wds[int(match)]}

                        self.logger.debug('{} {}'.format(alert['_id'],
                                          alert['xmatch']['nearest_within_5_arcsec']['Gaia_DR2_WD']['_id']))

                        matches_to_ingest.append(alert)

                        # generate previews for the endpoint
                        self.dump_cutout(alert, save_fits=False)
                        self.dump_lightcurve(alert)

            # raise Exception('HALT!!')

        # collection_obs
        # ingest every matched object into own db. It's not that many, so just dump everything
        if len(matches_to_ingest) > 0:
            self.insert_multiple_db_entries(_collection=self.config['database']['collection_obs'],
                                            _db_entries=matches_to_ingest)

        self.logger.info(f'total detected: {total_detected}')

        self.logger.info('Creating 2d index')
        self.db['db'][self.config['database']['collection_obs']].create_index([('coordinates.radec_geojson',
                                                                                '2dsphere')])

        self.logger.info('All done')

    def shutdown(self):
        self.kowalski.close()


def main(_config_file: str, _all: bool):
    """
        Cross-match a night worth of ZTF alerts with a catalog of white dwarfs from Gaia DR2
    """

    wd = WhiteDwarf(config_file=_config_file)

    wd.run(_all)

    wd.shutdown()


if __name__ == '__main__':
    ''' Create command line argument parser '''
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description='Fetch White Dwarfs detected with ZTF (last night)')

    parser.add_argument('config_file', metavar='config_file',
                        action='store', help='path to config file.', type=str)
    parser.add_argument('--all', action='store_true',
                        help='fetch all alerts available available on Kowalski')

    args = parser.parse_args()

    main(_config_file=args.config_file, _all=args.all)
