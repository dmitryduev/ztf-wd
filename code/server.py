import traceback
from astropy.time import Time
import flask
import flask_login
import flask_pymongo
import os
import json
from werkzeug.security import generate_password_hash, check_password_hash
from bson.json_util import loads, dumps
import datetime
import pytz
import logging
from ast import literal_eval


from utils import utc_now, jd, get_config
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

# set up secret key:
app.secret_key = config['server']['SECRET_KEY']

# config db
app.config["MONGO_URI"] = f"mongodb://{config['database']['user']}:{config['database']['pwd']}@" + \
                          f"{config['database']['host']}:{config['database']['port']}/{config['database']['db']}"
mongo = flask_pymongo.PyMongo(app)


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
    # check if username exists and passwords match
    # look up in the database first:
    select = mongo.db.users.find_one({'_id': username})
    if select is not None and \
            check_password_hash(select['password'], flask.request.form['password']):
        user = User()
        user.id = username
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


@app.route('/', methods=['GET'])
# @flask_login.login_required
def root():
    """
        Endpoint for the web GUI homepage
    :return:
    """
    # return flask.render_template('template.html')
    try:
        user_id = str(flask_login.current_user.id)
    except Exception as e:
        print(e)
        user_id = None

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
def alerts(candid):
    try:
        user_id = str(flask_login.current_user.id)
    except Exception as e:
        print(e)
        user_id = None

    download = flask.request.args.get('download', None, str)
    # print(download)

    # print(candid)

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


@app.route('/search', methods=['GET', 'POST'])
def search():
    """
        Endpoint for the web GUI search page
    :return:
    """
    if flask_login.current_user.is_anonymous:
        user_id = None
    else:
        user_id = str(flask_login.current_user.id)

    print(user_id)

    # messages = []

    # alerts = list(cursor) if cursor is not None else []
    # alerts = []
    alerts = [mongo.db.ZTF_alerts.find_one()]

    # TODO: yield from pymongo cursor instead of converting to list all at once

    return flask.Response(stream_template('template-search.html',
                                          user=user_id,
                                          logo=config['server']['logo'],
                                          form=flask.request.form,
                                          alerts=alerts))


if __name__ == '__main__':
    app.run(host=config['server']['host'], port=config['server']['port'], threaded=True)