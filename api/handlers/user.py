from tornado.web import authenticated

from api.encryption import aes_decrypt

from .auth import AuthHandler

class UserHandler(AuthHandler):

    @authenticated
    def get(self):
        self.set_status(200)
        self.response['email'] = aes_decrypt(self.current_user['email'])
        self.response['displayName'] = aes_decrypt(self.current_user['display_name'])
        self.response['fullName'] = aes_decrypt(self.current_user['full_name'])
        self.response['address'] = aes_decrypt(self.current_user['address'])
        self.response['dob'] = aes_decrypt(self.current_user['dob'])
        self.response['phoneNumber'] = aes_decrypt(self.current_user['phone_number'])
        self.response['disabilities'] = aes_decrypt(self.current_user['disabilities'])
        self.write_json()
