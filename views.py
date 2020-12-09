from flask import render_template, make_response
from flask_restful import Api, Resource, reqparse, abort
from app import app
from db_config import db
from models import UserModel, RevokedTokenModel
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
import werkzeug, os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["500 per day", "10 per minute", "1 per second"],
)

# Api class instance api of app from flask_restful
api = Api(app)

# app instance to JWTManager class
jwt = JWTManager(app)


app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return RevokedTokenModel.is_jti_blacklisted(jti)


# Parser for Registration and Login 
parser = reqparse.RequestParser()
parser.add_argument('username', type = str, help = 'This field can not be Blank.', required=True)
parser.add_argument('password', type = str, help = 'This field can not be Blank.', required=True)


UPLOAD_FOLDER = 'static/img'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# Image upload parser
img_parser = reqparse.RequestParser()
img_parser.add_argument('file', type = werkzeug.datastructures.FileStorage, location = 'files')



class UserRegistration(Resource):
    decorators = [limiter.exempt]
    def post(self):
        data = parser.parse_args()

        if UserModel.find_by_username(data['username']):
            return abort(409, message="User {} already exists.".format(data['username']))
        
        new_user = UserModel(
            username = data['username'],
            password = UserModel.generate_hash(data['password'])
        )
        try:
            new_user.save_to_db()

            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])

            return {
                'message': 'User {} got created.'.format(data['username']),
                'access_token': access_token,
                'refresh_token': refresh_token
                }, 201
        except:
            return {'message': 'Something went wrong'}, 500


class UserLogin(Resource):
    def post(self):
        data = parser.parse_args()
        current_user = UserModel.find_by_username(data['username'])

        if not current_user:
            return abort(404, message = "User {} doesn't exist.".format(data['username']))

        if UserModel.verify_hash(data['password'], current_user.password):
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            return {
                'message': 'Logged in as {}'.format(current_user.username),
                'access_token': access_token,
                'refresh_token': refresh_token
                }, 200
        else:
            return {'message': 'Wrong credentials'}, 401


class UserLogoutAccess(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'Access token has been revoked'}, 201
        except:
            return {'message': 'Something went wrong'}, 500



class UserLogoutRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'Refresh token has been revoked'}, 201
        except:
            return {'message': 'Something went wrong'}, 500


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity = current_user)
        return {'access_token': access_token}, 200


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


class UploadImage(Resource):
    decorators = [limiter.limit("3 per minute")]
    def post(self):
        data = img_parser.parse_args()
        image_file = data['file']
        
        if not image_file:
            return {'message': 'No file is selected for upload'}, 404
        
        image_file_name = image_file.filename

        if image_file:
            if allowed_file(image_file_name):
                filename = werkzeug.utils.secure_filename(image_file_name)
                image_file.save(os.path.join(UPLOAD_FOLDER, filename))
                return make_response(render_template('profile.html', filename=filename))
                

            else:
                return {'message': 'Please upload files of extensions jpg, png, jpeg, gif'}, 400
        return {'message': 'Something went wrong'}, 500


api.add_resource(UserRegistration, '/registration')
api.add_resource(UserLogin, '/login')
api.add_resource(UserLogoutAccess, '/logout/access')
api.add_resource(UserLogoutRefresh, '/logout/refresh')
api.add_resource(TokenRefresh, '/token/refresh')
api.add_resource(UploadImage, '/image-upload')


if __name__ == "__main__":
    app.run(debug=True, port=3000)