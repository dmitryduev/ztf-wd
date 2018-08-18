import traceback
from astropy.time import Time
import flask
import flask_login
import flask_pymongo
from flask_jwt_extended import JWTManager, jwt_required, jwt_optional, create_access_token, get_jwt_identity
# from flask_misaka import Misaka
import os
import json
from werkzeug.security import generate_password_hash, check_password_hash
from bson.json_util import loads, dumps
import datetime
import pytz
import logging
from ast import literal_eval
import requests
import numpy as np


from utils import utc_now, jd, get_config, radec_str2geojson
# from .utils import utc_now, jd, get_config


def to_pretty_json(value):
    # return dumps(value, indent=4)  # , separators=(',', ': ')
    return dumps(value, separators=(',', ': '))


def add_admin():
    """
        Create admin user for the web interface if it does not exists already
    :param _mongo:
    :param _secrets:
    :return:
    """
    ex_admin = mongo.db.users.find_one({'_id': secrets['database']['admin_username']})
    if ex_admin is None:
        mongo.db.users.insert_one({'_id': secrets['database']['admin_username'],
                                   'password': generate_password_hash(secrets['database']['admin_password']),
                                   'permissions': {},
                                   'last_modified': utc_now()
                                   })


''' load config '''
config = get_config('/app/config.json')

''' load secrets '''
with open('/app/secrets.json') as sjson:
    secrets = json.load(sjson)

''' initialize the Flask app '''
app = flask.Flask(__name__)
# add 'do' statement to jinja environment (does the same as {{ }}, but returns nothing):
app.jinja_env.add_extension('jinja2.ext.do')

# add json prettyfier
app.jinja_env.filters['tojson_pretty'] = to_pretty_json

# set up secret keys:
app.secret_key = config['server']['SECRET_KEY']
app.config['JWT_SECRET_KEY'] = config['server']['SECRET_KEY']

# config db
app.config["MONGO_URI"] = f"mongodb://{config['database']['user']}:{config['database']['pwd']}@" + \
                          f"{config['database']['host']}:{config['database']['port']}/{config['database']['db']}"
mongo = flask_pymongo.PyMongo(app)

# Setup the Flask-JWT-Extended extension
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=30)
jwt = JWTManager(app)

# add admin if run first time:
add_admin()

''' login management'''
login_manager = flask_login.LoginManager()
login_manager.init_app(app)


class User(flask_login.UserMixin):
    pass


@login_manager.user_loader
def user_loader(username):
    select = mongo.db.users.find_one({'_id': username})
    if select is None:
        # return None
        return

    user = User()
    user.id = username
    return user


@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    # look up in the database
    select = mongo.db.users.find_one({'_id': username})
    if select is None:
        return

    user = User()
    user.id = username

    try:
        user.is_authenticated = check_password_hash(select['password'], flask.request.form['password'])

    except Exception as _e:
        print(_e)
        # return None
        return

    return user


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
        Endpoint for login through the web interface
    :return:
    """
    # print(flask_login.current_user)
    if flask.request.method == 'GET':
        # logged in already?
        if flask_login.current_user.is_authenticated:
            return flask.redirect(flask.url_for('root'))
        # serve template if not:
        else:
            return flask.render_template('template-login.html', logo=config['server']['logo'])
    # print(flask.request.form['username'], flask.request.form['password'])

    # print(flask.request)

    username = flask.request.form['username']
    password = flask.request.form['password']
    # check if username exists and passwords match
    # look up in the database first:
    select = mongo.db.users.find_one({'_id': username})
    if select is not None and check_password_hash(select['password'], password):
        user = User()
        user.id = username

        # get a JWT token to use API:
        try:
            # post username and password, get access token
            auth = requests.post('http://localhost:{}/auth'.format(config['server']['port']),
                                 json={"username": username, "password": password})
            access_token = auth.json()['access_token'] if 'access_token' in auth.json() else 'FAIL'
        except Exception as e:
            print(e)
            access_token = 'FAIL'

        user.access_token = access_token
        # print(user, user.id, user.access_token)
        # save to session:
        flask.session['access_token'] = access_token

        flask_login.login_user(user, remember=True)
        return flask.redirect(flask.url_for('root'))
    else:
        # serve template with flag fail=True to display fail message
        return flask.render_template('template-login.html', logo=config['server']['logo'],
                                     messages=[(u'Failed to log in.', u'danger')])


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    """
        Log user out
    :return:
    """
    if 'access_token' in flask.session:
        flask.session.pop('access_token')

    flask_login.logout_user()
    return flask.redirect(flask.url_for('root'))


@app.errorhandler(500)
def internal_error(error):
    return '500 error'


@app.errorhandler(404)
def not_found(error):
    return '404 error'


@app.errorhandler(403)
def forbidden(error):
    return '403 error: forbidden'


@login_manager.unauthorized_handler
def unauthorized_handler():
    return flask.redirect(flask.url_for('login'))


# manage users
@app.route('/users', methods=['GET'])
@flask_login.login_required
def manage_users():
    if flask_login.current_user.id == 'admin':
        # fetch users from the database:
        _users = {}

        cursor = mongo.db.users.find()
        for usr in cursor:
            # print(usr)
            # TODO: might want to fetch more data in the future
            _users[usr['_id']] = {'permissions': usr['permissions']}
        cursor.close()

        return flask.render_template('template-users.html',
                                     user=flask_login.current_user.id,
                                     logo=config['server']['logo'],
                                     users=_users,
                                     current_year=datetime.datetime.now().year)
    else:
        flask.abort(403)


@app.route('/users', methods=['PUT'])
@flask_login.login_required
def add_user():
    """
        Add new user to DB
    :return:
    """
    if flask_login.current_user.id == secrets['database']['admin_username']:
        try:
            print(flask.request.args)
            user = flask.request.args['user']
            password = flask.request.args['password']
            permissions = flask.request.args['permissions']

            if len(user) == 0 or len(password) == 0:
                return 'everything must be set'

            # add user to coll_usr collection:
            mongo.db.users.insert_one(
                {'_id': user,
                 'password': generate_password_hash(password),
                 'permissions': literal_eval(str(permissions)),
                 'last_modified': datetime.datetime.now()}
            )

            return 'success'

        except Exception as _e:
            print(_e)
            return str(_e)
    else:
        flask.abort(403)


@app.route('/users', methods=['POST'])
@flask_login.login_required
def edit_user():
    """
        Edit user info
    :return:
    """

    if flask_login.current_user.id == secrets['database']['admin_username']:
        try:
            # print(flask.request.args)
            id = flask.request.args['_user']
            user = flask.request.args['edit-user']
            password = flask.request.args['edit-password']
            permissions = flask.request.args['edit-permissions']

            if id == secrets['database']['admin_username'] and user != secrets['database']['admin_username']:
                return 'Cannot change the admin username!'

            if len(user) == 0:
                return 'username must be set'

            # change username:
            if id != user:
                select = mongo.db.users.find_one({'_id': id})
                select['_id'] = user
                mongo.db.users.insert_one(select)
                mongo.db.users.delete_one({'_id': id})

            # change password:
            if len(password) != 0:
                result = mongo.db.users.update(
                    {'_id': id},
                    {
                        '$set': {
                            'password': generate_password_hash(password)
                        },
                        '$currentDate': {'last_modified': True}
                    }
                )

            # change permissions:
            if len(permissions) != 0:
                select = mongo.db.users.find_one({'_id': id}, {'_id': 0, 'permissions': 1})
                # print(select['permissions'])
                # print(permissions)
                _p = literal_eval(str(permissions))
                # print(_p)
                if str(permissions) != str(select['permissions']):
                    result = mongo.db.users.update(
                        {'_id': id},
                        {
                            '$set': {
                                'permissions': _p
                            },
                            '$currentDate': {'last_modified': True}
                        }
                    )

            return 'success'
        except Exception as _e:
            print(_e)
            return str(_e)
    else:
        flask.abort(403)


@app.route('/users', methods=['DELETE'])
@flask_login.login_required
def remove_user():
    """
        Remove user from DB
    :return:
    """
    if flask_login.current_user.id == secrets['database']['admin_username']:
        try:
            # print(flask.request.args)
            # get username from request
            user = flask.request.args['user']
            if user == 'admin':
                return 'Cannot remove the admin!'
            # print(user)

            # try to remove the user:
            mongo.db.users.delete_one({'_id': user})

            return 'success'
        except Exception as _e:
            print(_e)
            return str(_e)
    else:
        flask.abort(403)


@app.route('/auth', methods=['POST'])
def auth():
    """
        Issue a JSON web token (JWT) for a registered user.
        To be used with API
    :return:
    """
    try:
        if not flask.request.is_json:
            return flask.jsonify({"msg": "Missing JSON in request"}), 400

        username = flask.request.json.get('username', None)
        password = flask.request.json.get('password', None)
        if not username:
            return flask.jsonify({"msg": "Missing username parameter"}), 400
        if not password:
            return flask.jsonify({"msg": "Missing password parameter"}), 400

        # check if username exists and passwords match
        # look up in the database first:
        select = mongo.db.users.find_one({'_id': username})
        if select is not None and check_password_hash(select['password'], password):
            # Identity can be any data that is json serializable
            access_token = create_access_token(identity=username)
            return flask.jsonify(access_token=access_token), 200
        else:
            return flask.jsonify({"msg": "Bad username or password"}), 401

    except Exception as _e:
        print(_e)
        return flask.jsonify({"msg": "Something unknown went wrong"}), 400


@app.route('/', methods=['GET'])
# @flask_login.login_required
def root():
    """
        Endpoint for the web GUI homepage
    :return:
    """
    if flask_login.current_user.is_anonymous:
        user_id = None
    else:
        user_id = str(flask_login.current_user.id)

    # messages = []

    # get time range:
    date_start = flask.request.args.get('start', datetime.datetime.utcnow().strftime('%Y%m%d'), str)
    date_end = flask.request.args.get('end', datetime.datetime.utcnow().strftime('%Y%m%d'), str)

    # print(date_start, date_end)

    # compute jd range:
    dt_start = datetime.datetime.strptime(date_start, '%Y%m%d')
    jd_start = Time(dt_start).jd
    if date_end == date_start:
        dt_end = dt_start + datetime.timedelta(days=1)
        jd_end = Time(dt_end).jd
    else:
        dt_end = datetime.datetime.strptime(date_end, '%Y%m%d') + datetime.timedelta(days=1)
        jd_end = Time(dt_end).jd

    # print(jd_start, jd_end)

    # get white dwarfs detected in jd time range
    if user_id is None:
        # Anonymous only gets MSIP data
        cursor = mongo.db.ZTF_alerts.find({'candidate.jd': {'$gt': jd_start, '$lt': jd_end},
                                           'candidate.programid': {'$eq': 1}},
                                          {'cutoutScience': 0, 'cutoutTemplate': 0, 'cutoutDifference': 0})
    else:
        # Shri gets it all
        cursor = mongo.db.ZTF_alerts.find({'candidate.jd': {'$gt': jd_start, '$lt': jd_end}},
                                          {'cutoutScience': 0, 'cutoutTemplate': 0, 'cutoutDifference': 0})

    alerts = list(cursor) if cursor is not None else []

    # TODO: yield from pymongo cursor instead of converting to list all at once

    return flask.Response(stream_template('template-root.html',
                                          user=user_id,
                                          logo=config['server']['logo'],
                                          start=date_start, end=date_end,
                                          alerts=alerts))


def stream_template(template_name, **context):
    """
        see: http://flask.pocoo.org/docs/0.11/patterns/streaming/
    :param template_name:
    :param context:
    :return:
    """
    app.update_template_context(context)
    t = app.jinja_env.get_template(template_name)
    rv = t.stream(context)
    rv.enable_buffering(5)
    return rv


@app.route('/data/<path:filename>')
# @flask_login.login_required
def data_static(filename):
    """
        Get files from the archive
    :param filename:
    :return:
    """
    _p, _f = os.path.split(filename)
    return flask.send_from_directory(os.path.join(config['path']['path_alerts'], _p), _f)


# alerts REST
@app.route('/alerts/<candid>', methods=['GET'])
# @jwt_optional
def alerts(candid):
    try:
        user_id = str(flask_login.current_user.id)
    except Exception as e:
        print(e)
        user_id = None

    download = flask.request.args.get('download', None, str)
    # print(download)

    # print(candid)

    # bypass /alerts API and get it this way (it's faster)
    alert = mongo.db.ZTF_alerts.find_one({'candid': int(candid)})
    # print(alert)

    if alert is not None and len(alert) != 0:
        if alert['candidate']['programid'] != 1:
            try:
                if flask_login.current_user.id == 'admin':
                    if download is not None:
                        return flask.Response(dumps(alert), mimetype='application/json')
                    else:
                        return flask.render_template('template-alert.html',
                                                     user=user_id,
                                                     alert=alert,
                                                     logo=config['server']['logo'])
                else:
                    flask.abort(403)
            except Exception as e:
                # for now, only _admin_ can access non-MSIP data
                print(e)
                flask.abort(403)
        else:
            if download is not None:
                return flask.Response(dumps(alert), mimetype='application/json')
            else:
                return flask.render_template('template-alert.html',
                                             user=user_id,
                                             alert=alert,
                                             logo=config['server']['logo'])
    else:
        # couldn't find it
        flask.abort(404)


@app.route('/alerts', methods=['POST'])
@jwt_optional
def get_alerts():
    try:
        current_user = get_jwt_identity()

        # print(current_user)

        if current_user is not None:
            user_id = str(current_user)

        else:
            # unauthorized
            # return flask.jsonify({"msg": "Unauthorized access attempt"}), 401
            user_id = None

    except Exception as e:
        print(e)
        user_id = None

    query = flask.request.json
    # print(query)

    # prevent fraud: TODO: can add custom user permissions in the future
    if user_id is None:
        query['filter'] = {'$and': [{'candidate.programid': 1}, query['filter']]}

    if len(query['projection']) == 0:
        cursor = mongo.db.ZTF_alerts.find(query['filter'])  # .limit(2)
    else:
        cursor = mongo.db.ZTF_alerts.find(query['filter'], query['projection'])  # .limit(2)

    _alerts = list(cursor) if cursor is not None else []

    return flask.Response(dumps(_alerts), mimetype='application/json')


@app.route('/search', methods=['GET', 'POST'])
def search():
    """
        Endpoint for the web GUI search page
    :return:
    """
    if flask_login.current_user.is_anonymous:
        user_id = None
        access_token = None
    else:
        user_id = str(flask_login.current_user.id)
        access_token = flask.session['access_token']

    # try:
    #     print(flask.session)
    #     print(flask.session['access_token'])
    #     print(flask_login.current_user.id, flask_login.current_user.access_token)
    # except Exception as e:
    #     print(e)

    # print(user_id)

    messages = []

    # alerts = list(cursor) if cursor is not None else []
    _alerts = []

    # got a request?
    if flask.request.method == 'POST':
        try:
            form = flask.request.form
            # print(form)

            # convert to filter and projection to run a find() query with the API:
            query = {'filter': {},
                     'projection': {}}

            objects = literal_eval(form['radec'].strip())

            if isinstance(objects, list):
                object_coordinates = objects
                object_names = [str(obj_crd) for obj_crd in object_coordinates]
            elif isinstance(objects, dict):
                object_names, object_coordinates = zip(*objects.items())
                object_names = list(map(str, object_names))
            else:
                raise ValueError('Unsupported type of object coordinates')

            cone_search_radius = float(form['cone_search_radius'])
            # convert to rad:
            if form['cone_search_unit'] == 'arcsec':
                cone_search_radius *= np.pi / 180.0 / 3600.
            elif form['cone_search_unit'] == 'arcmin':
                cone_search_radius *= np.pi / 180.0 / 60.
            elif form['cone_search_unit'] == 'deg':
                cone_search_radius *= np.pi / 180.0
            elif form['cone_search_unit'] == 'rad':
                cone_search_radius *= 1
            else:
                raise Exception('Unknown cone search unit. Must be in [deg, rad, arcsec, arcmin]')

            # print(objects)
            # print(cone_search_radius)

            # get only programid=1 data for anonymous users:
            query['filter']['$and'] = [{'candidate.programid': {'$eq': 1}}] if user_id is None else []

            query['filter']['$and'].append({'$or': []})

            for oi, obj_crd in enumerate(object_coordinates):
                # convert ra/dec into GeoJSON-friendly format
                # print(obj_crd)
                _ra, _dec = radec_str2geojson(*obj_crd)

                query['filter']['$and'][-1]['$or'].append({'coordinates.radec_geojson':
                                                           {'$geoWithin': {'$centerSphere': [[_ra, _dec],
                                                                                             cone_search_radius]}}})

            # query own API:
            if access_token is not None:
                r = requests.post(os.path.join('http://', f"localhost:{config['server']['port']}", 'alerts'),
                                  json=query,
                                  headers={'Authorization': 'Bearer {:s}'.format(access_token)})
            else:
                r = requests.post(os.path.join('http://', f"localhost:{config['server']['port']}", 'alerts'),
                                  json=query)

            _alerts = r.json()
            # print(_alerts)

            if len(_alerts) == 0:
                messages = [(u'Did not find anything.', u'info')]

        except Exception as e:
            print(e)
            messages = [(u'Failed to digest query.', u'danger')]

    return flask.Response(stream_template('template-search.html',
                                          user=user_id,
                                          logo=config['server']['logo'],
                                          form=flask.request.form,
                                          alerts=_alerts,
                                          messages=messages))


if __name__ == '__main__':
    app.run(host=config['server']['host'], port=config['server']['port'], threaded=True)