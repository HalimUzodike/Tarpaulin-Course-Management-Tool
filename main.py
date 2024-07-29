from flask import Flask, request, jsonify, send_file
from google.cloud import datastore, storage
import io
import requests
import json
from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

PHOTO_BUCKET = 'm8_photos_uzodikec'

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

USERS = "users"
COURSES = "courses"

CLIENT_ID = 'SjHUwvMyUiraA33ccF8NR07lTcwuA1po'
CLIENT_SECRET = '6oVfgpi1KfFY8Rl_hxUZvL6z-HbPWT1t2-p0FgMzvuaXEmWkpJebYWcsmwr3XOFA'
DOMAIN = 'dev-oeqfviw80bsmu6ci.us.auth0.com'

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                         "description":
                             "Authorization header is missing"}, 401)

    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                             "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                             "description":
                                 "incorrect claims,"
                                 " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                             "description":
                                 "Unable to parse authentication"
                                 " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                         "description":
                             "No RSA key in JWKS"}, 401)


@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return jsonify(payload), 200


@app.route('/')
def index():
    return "Halim Final Project CS 493"


@app.route('/' + USERS + '/login', methods=['POST'])
def login_user():
    """
    1st Endpoint: Login user
    :return: Returns a JWT token if the user is authenticated
    """
    content = request.get_json()

    required_fields = ["username", "password"]
    if not all(field in content for field in required_fields):
        return {"Error": "The request body is invalid"}, 400

    username = content["username"]
    password = content["password"]
    body = {'grant_type': 'password', 'username': username,
            'password': password,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
            }
    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'

    resp = requests.post(url, json=body, headers=headers)
    resp_data = resp.json()

    if 'id_token' not in resp_data:
        return {"Error": "Unauthorized"}, 401

    return {'token': resp_data['id_token']}, 200


@app.route('/' + USERS, methods=['GET'])
def get_all_users():
    """
    2nd Endpoint: Get all users
    :return: Returns a list of all users
    """
    if 'Authorization' in request.headers:
        try:
            payload = verify_jwt(request)
        except Exception as e:
            print(e)
            return {"Error": "Unauthorized"}, 401

        admin_query = client.query(kind=USERS)
        admin_query.add_filter('sub', '=', payload['sub'])
        admin_query.add_filter('role', '=', "admin")
        results = list(admin_query.fetch())

        if results:
            user_query = client.query(kind=USERS)
            results = list(user_query.fetch())
            for r in results:
                r['id'] = r.key.id
            return jsonify([{'id': user['id'], 'role': user['role'], 'sub': user['sub']} for user in results]), 200

        else:
            return {"Error": "You don't have permission on this resource"}, 403


@app.route('/' + USERS + '/<int:id>', methods=['GET'])
def get_user(id):
    """
    3rd Endpoint: Get a user by id
    :param id:
    :return: Returns a user by id
    """
    try:
        payload = verify_jwt(request)
    except Exception as e:
        print(e)
        return {"Error": "Unauthorized"}, 401

    user_key = client.key(USERS, id)
    user = client.get(key=user_key)

    if user is None:
        return {"Error": "Not found"}, 404

    user['id'] = user.key.id

    blob_name = str(id) + ".png"
    blob = storage.Client().bucket(PHOTO_BUCKET).blob(blob_name)
    if blob.exists():
        user['avatar_url'] = request.base_url + "/avatar"

    if user['role'] == 'student':
        user['courses'] = []

        course_query = client.query(kind=COURSES)
        course_query.add_filter('enrollment', '=', user.key.id)
        results = list(course_query.fetch())

        for course in results:
            user['courses'].append(course.key.id)

    if user['role'] == 'instructor':
        user['courses'] = []
        course_query = client.query(kind=COURSES)
        course_query.add_filter('instructor_id', '=', id)
        results = list(course_query.fetch())

        for course in results:
            course_url = request.base_url + "/../courses/" + str(course.key.id)
            user['courses'].append(course_url)

    admin_query = client.query(kind=USERS)
    admin_query.add_filter('sub', '=', payload['sub'])
    admin_query.add_filter('role', '=', "admin")
    admin_results = list(admin_query.fetch())

    if payload['sub'] == user['sub'] or (admin_results and admin_results[0]['sub'] == payload['sub']):
        return jsonify(user), 200
    else:
        return {"Error": "You don't have permission on this resource"}, 403


@app.route('/' + USERS + '/<int:id>/avatar', methods=['POST'])
def create_update_avatar(id):
    """
    4th Endpoint: Create or update user avatar
    :param id:
    :return: Returns the avatar url
    """
    if 'file' not in request.files:
        return {"Error": "The request body is invalid"}, 400

    try:
        payload = verify_jwt(request)
    except Exception as e:
        print(e)
        return {"Error": "Unauthorized"}, 401

    user_key = client.key(USERS, id)
    user = client.get(key=user_key)

    if user is None:
        return {"Error": "Not found"}, 404

    if payload['sub'] != user['sub']:
        return {"Error": "You don't have permission on this resource"}, 403

    file_obj = request.files['file']
    blob_name = str(id) + ".png"
    blob = storage.Client().bucket(PHOTO_BUCKET).blob(blob_name)
    blob.upload_from_file(file_obj)

    resp = {'avatar_url': request.base_url}
    return jsonify(resp), 200


@app.route('/' + USERS + '/<int:id>/avatar', methods=['GET'])
def get_user_avatar(id):
    """
    5th Endpoint: Get user's avatar
    :param id:
    :return: Returns the user avatar
    """
    try:
        payload = verify_jwt(request)
    except Exception as e:
        print(e)
        return {"Error": "Unauthorized"}, 401

    user_key = client.key(USERS, id)
    user = client.get(key=user_key)

    if user is None:
        return {"Error": "Not found"}, 404

    if payload['sub'] != user['sub']:
        return {"Error": "You don't have permission on this resource"}, 403

    blob_name = str(id) + ".png"
    blob = storage.Client().bucket(PHOTO_BUCKET).blob(blob_name)
    if blob.exists():
        file_obj = io.BytesIO()
        blob.download_to_file(file_obj)
        file_obj.seek(0)
        return send_file(file_obj, mimetype='image/png')

    return {"Error": "Not found"}, 404


@app.route('/' + USERS + '/<int:id>/avatar', methods=['DELETE'])
def delete_user_avatar(id):
    """
    6th Endpoint: Delete user's avatar
    :param id:
    :return: Returns an empty response
    """
    try:
        payload = verify_jwt(request)
    except Exception as e:
        print(e)
        return {"Error": "Unauthorized"}, 401

    user_key = client.key(USERS, id)
    user = client.get(key=user_key)

    if user is None:
        return {"Error": "Not found"}, 404

    if payload['sub'] != user['sub']:
        return {"Error": "You don't have permission on this resource"}, 403

    blob_name = str(id) + ".png"
    blob = storage.Client().bucket(PHOTO_BUCKET).blob(blob_name)
    if blob.exists():
        blob.delete()
        return '', 204

    return {"Error": "Not found"}, 404


@app.route('/' + COURSES, methods=['POST'])
def create_course():
    """
    7th Endpoint: Create a course
    :return: Returns the created course
    """
    try:
        payload = verify_jwt(request)
    except Exception as e:
        print(e)
        return {"Error": "Unauthorized"}, 401

    admin_query = client.query(kind=USERS)
    admin_query.add_filter('sub', '=', payload['sub'])
    admin_query.add_filter('role', '=', "admin")
    results = list(admin_query.fetch())

    if not results:
        return {"Error": "You don't have permission on this resource"}, 403

    content = request.get_json()
    required_fields = ["subject", "number", "title", "term", "instructor_id"]
    if not all(field in content for field in required_fields):
        return {"Error": "The request body is invalid"}, 400

    instructor_query = client.query(kind=USERS)
    instructor_query.add_filter('role', '=', 'instructor')
    instructor_query.add_filter('__key__', '=', client.key(USERS, content["instructor_id"]))
    instructor_results = list(instructor_query.fetch())

    if not instructor_results:
        return {"Error": "The request body is invalid"}, 400

    new_course = datastore.entity.Entity(key=client.key(COURSES))
    new_course.update({"subject": content["subject"], "number": content["number"],
                       "title": content["title"], "term": content["term"],
                       "instructor_id": content["instructor_id"]})
    client.put(new_course)

    self_url = request.base_url + '/' + str(new_course.key.id)
    new_course['id'] = new_course.key.id
    new_course['self'] = self_url

    return jsonify(new_course), 201


@app.route('/' + COURSES, methods=['GET'])
def get_all_courses():
    """
    8th Endpoint: Get all courses
    :return: Returns a list of all courses
    """
    offset = int(request.args.get('offset', '0'))
    limit = int(request.args.get('limit', '3'))

    course_query = client.query(kind=COURSES)
    results = list(course_query.fetch(offset=offset, limit=limit))

    sorted_results = sorted(results, key=lambda x: x['subject'])

    for r in sorted_results:
        r['id'] = r.key.id
        r['self'] = request.base_url + '/' + str(r.key.id)

    resp = {"courses": sorted_results}

    if len(sorted_results) == limit:
        resp["next"] = request.base_url + "?offset={}&limit={}".format(offset + limit, limit)

    return jsonify(resp), 200


@app.route('/' + COURSES + '/<int:id>', methods=['GET'])
def get_course(id):
    """
    9th Endpoint: Get a course by id
    :param id:
    :return: Returns a course by id
    """
    course_key = client.key(COURSES, id)
    course = client.get(key=course_key)

    if course is None:
        return {"Error": "Not found"}, 404

    course['id'] = course.key.id
    course['self'] = request.base_url

    return jsonify(course), 200


# Below this line are the untested endpoints. Remember to develop unique tests for these using Postman

@app.route('/' + COURSES + '/<int:id>', methods=['PATCH'])
def update_course(id):
    """
    10th Endpoint: Update a course
    :param id:
    :return: Returns the updated course
    """
    try:
        payload = verify_jwt(request)
    except Exception as e:
        print(e)
        return {"Error": "Unauthorized"}, 401

    admin_query = client.query(kind=USERS)
    admin_query.add_filter('sub', '=', payload['sub'])
    admin_query.add_filter('role', '=', "admin")
    results = list(admin_query.fetch())

    if not results:
        return {"Error": "You don't have permission on this resource"}, 403

    course_key = client.key(COURSES, id)
    course = client.get(key=course_key)

    if course is None:
        return {"Error": "Not found"}, 404

    content = request.get_json()

    if "instructor_id" in content:
        instructor_query = client.query(kind=USERS)
        instructor_query.add_filter('role', '=', 'instructor')
        instructor_query.add_filter('__key__', '=', client.key(USERS, content["instructor_id"]))
        instructor_results = list(instructor_query.fetch())

        if not instructor_results:
            return {"Error": "The request body is invalid"}, 400
        course["instructor_id"] = content["instructor_id"]

    if "subject" in content:
        course["subject"] = content["subject"]
    if "number" in content:
        course["number"] = content["number"]
    if "title" in content:
        course["title"] = content["title"]
    if "term" in content:
        course["term"] = content["term"]

    client.put(course)

    course['id'] = course.key.id
    course['self'] = request.base_url

    return jsonify(course), 200


@app.route('/' + COURSES + '/<int:id>', methods=['DELETE'])
def delete_course(id):
    """
    11th Endpoint: Delete a course
    :param id:
    :return: Returns an empty response
    """
    try:
        payload = verify_jwt(request)
    except Exception as e:
        print(e)
        return {"Error": "Unauthorized"}, 401

    admin_query = client.query(kind=USERS)
    admin_query.add_filter('sub', '=', payload['sub'])
    admin_query.add_filter('role', '=', "admin")
    results = list(admin_query.fetch())

    if not results:
        return {"Error": "You don't have permission on this resource"}, 403

    course_key = client.key(COURSES, id)
    course = client.get(key=course_key)

    if course is None:
        return {"Error": "Not found"}, 404

    client.delete(course_key)

    return '', 204


@app.route('/' + COURSES + '/<int:id>/students', methods=['PATCH'])
def update_course_enrollment(id):
    """
    12th Endpoint: Update course enrollment
    :param id:
    :return: Returns an empty response
    """
    try:
        payload = verify_jwt(request)
    except Exception as e:
        print(e)
        return {"Error": "Unauthorized"}, 401

    admin_query = client.query(kind=USERS)
    admin_query.add_filter('sub', '=', payload['sub'])
    admin_query.add_filter('role', '=', "admin")
    admin_results = list(admin_query.fetch())

    course_key = client.key(COURSES, id)
    course = client.get(key=course_key)

    if course is None:
        return {"Error": "Not found"}, 404

    instructor_query = client.query(kind=USERS)
    instructor_query.add_filter('__key__', '=', client.key(USERS, course["instructor_id"]))
    instructor_results = list(instructor_query.fetch())

    if not admin_results and payload['sub'] != instructor_results[0]['sub']:
        return {"Error": "You don't have permission on this resource"}, 403

    content = request.get_json()
    required_fields = ["add", "remove"]
    if not all(field in content for field in required_fields):
        return {"Error": "The request body is invalid"}, 400

    add_students = content["add"]
    remove_students = content["remove"]

    for student_id in add_students:
        student_key = client.key(USERS, student_id)
        student = client.get(key=student_key)
        if student and student['role'] == 'student' and student_key.id not in course.get("enrollment", []):
            course["enrollment"] = course.get("enrollment", []) + [student_key.id]

    for student_id in remove_students:
        student_key = client.key(USERS, student_id)
        student = client.get(key=student_key)
        if student and student['role'] == 'student' and student_key.id in course.get("enrollment", []):
            course["enrollment"].remove(student_key.id)

    client.put(course)

    return '', 200


@app.route('/' + COURSES + '/<int:id>/students', methods=['GET'])
def get_course_enrollment(id):
    """
    13th Endpoint: Get course enrollment
    :param id:
    :return: Returns a list of students enrolled in the course
    """
    try:
        payload = verify_jwt(request)
    except Exception as e:
        print(e)
        return {"Error": "Unauthorized"}, 401

    admin_query = client.query(kind=USERS)
    admin_query.add_filter('sub', '=', payload['sub'])
    admin_query.add_filter('role', '=', "admin")
    admin_results = list(admin_query.fetch())

    course_key = client.key(COURSES, id)
    course = client.get(key=course_key)

    if course is None:
        return {"Error": "Not found"}, 404

    instructor_query = client.query(kind=USERS)
    instructor_query.add_filter('__key__', '=', client.key(USERS, course["instructor_id"]))
    instructor_results = list(instructor_query.fetch())

    if not admin_results and payload['sub'] != instructor_results[0]['sub']:
        return {"Error": "You don't have permission on this resource"}, 403

    return jsonify(course.get("enrollment", [])), 200


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
