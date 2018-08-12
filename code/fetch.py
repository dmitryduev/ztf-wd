import datetime
from astropy.time import Time
import json
from penquins import Kowalski
import numpy as np
# import unittest

# with open('/app/crontest.txt', 'w') as f:
#     f.write(str(datetime.datetime.utcnow()))

from penquins import Kowalski

# load secrets:
# with open('/app/secrets.json') as sjson:
with open('/Users/dmitryduev/_caltech/python/ztf-wd/secrets.json') as sjson:
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


def cross_match(_kowalski, _jd, _stars, _fov_size_ref_arcsec=2, retries=3):

    for ir in range(retries):
        try:
            print(f'Querying Kowalski, attempt {ir+1}')
            # query Kowalski for Gaia stars:
            # if False:
            q = {"query_type": "cone_search",
                 "object_coordinates": {"radec": str(_stars),
                                        "cone_search_radius": str(_fov_size_ref_arcsec),
                                        "cone_search_unit": "arcsec"},
                 "catalogs": {"ZTF_alerts": {"filter": {},
                                             "projection": {"_id": 0, "objectId": 1,
                                                            "candid": 1,
                                                            "candidate.jd": 1,
                                                            "candidate.programid": 1,
                                                            "candidate.rb": 1,
                                                            "candidate.magpsf": 1,
                                                            "candidate.sigmapsf": 1}}}
                 }
            # {"candidate.jd": {"$gt": _jd, "$lt": _jd + 1}}
            # print(q)
            r = _kowalski.query(query=q, timeout=10)
            # print(r)
            matched_stars = r['result']['ZTF_alerts']

            return matched_stars

        except Exception as _e:
            print(_e)
            continue

    return None


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]


def main():
    """
        Cross-match a night worth of ZTF alerts with a catalog of white dwarfs from Gaia DR2
    """

    # compute current UTC. the script is run everyday at 19:00 UTC (~noon in LA)
    utc_date = datetime.datetime.utcnow()
    utc_date = datetime.datetime(utc_date.year, utc_date.month, utc_date.day)

    # convert to jd
    jd_date = Time(utc_date).jd
    print(utc_date, jd_date)

    # connect to Kowalski
    # get WD coordinates (extracted from Kowalski)
    # with open('/app/wds.20180811.json') as wdjson:
    with open('/Users/dmitryduev/_caltech/python/ztf-wd/code/wds.20180811.json') as wdjson:
        wds = json.load(wdjson)['query_result']
    # print(wds[:3])

    total_detected = 0

    with Kowalski(username=secrets['kowalski']['user'],
                  password=secrets['kowalski']['password']) as kowalski:
        # host='localhost', port=8082, protocol='http'

        # for batch_size run a cross match with ZTF_alerts for current UTC
        for ic, chunk in enumerate(chunks(wds, 1000)):
            print(f'Chunk #{ic}')
            # print(chunk[0]['_id'])

            stars = [(c['ra'], c['dec']) for c in chunk]
            # print(stars)

            matches = cross_match(kowalski, _jd=jd_date, _stars=stars, _fov_size_ref_arcsec=2, retries=3)
            non_empty_matches = {m: v for m, v in matches.items() if v is not None}
            print(len(non_empty_matches))
            total_detected += len(non_empty_matches)
            print(f'total detected so far: {total_detected}')

            # raise Exception('HALT!!')

            # ingest every matched object into own db. for starters, just count the number

        print(f'total detected: {total_detected}')


if __name__ == '__main__':
    main()
