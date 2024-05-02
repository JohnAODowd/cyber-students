from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine

from api.encryption import aes_encrypt, hash_password
import os

from .base import BaseHandler

class RegistrationHandler(BaseHandler):

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception()
            
            full_name = body.get('fullName')
            if not isinstance(full_name, str):
                raise Exception()
            
            address = body.get('address')
            if not isinstance(address, str):
                raise Exception()
            
            dob = body.get('dob')
            if not isinstance(dob, str):
                raise Exception()
            
            phone_number = body.get('phoneNumber')
            if not isinstance(phone_number, str):
                raise Exception()
            
            disabilities = body.get('disabilities')
            if not isinstance(disabilities, str):
                raise Exception()

        except Exception as e:
            self.send_error(400, message='You must provide an email address, password, display name, address, date of birth, phone number and disabilities!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return
        
        if not full_name:
            self.send_error(400, message='The full name name is invalid!')
            return

        if not address:
            self.send_error(400, message='The address is invalid!')
            return

        if not dob:
            self.send_error(400, message='The date of birth is invalid!')
            return

        if not phone_number:
            self.send_error(400, message='The phone number is invalid!')
            return 

        if not disabilities:
            self.send_error(400, message='The disabilities are invalid!')
            return          

        user = yield self.db.users.find_one({
          'email': aes_encrypt(email)
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        # Generate a salt for the new user
        salt = os.urandom(16)
        salt = salt.hex()

        yield self.db.users.insert_one({
            'email': aes_encrypt(email),
            
            'salt': salt,
            'hashed_password': hash_password(salt, password),

            'displayName': aes_encrypt(display_name),
            'fullName': aes_encrypt(full_name),
            'address':aes_encrypt(address),
            'dob': aes_encrypt(dob),
            'phoneNumber': aes_encrypt(phone_number),
            'disabilities': aes_encrypt(disabilities)
        })

        self.set_status(200)
        self.response['email'] = email
        self.response['displayName'] = display_name
        self.response['fullName'] = full_name
        self.response['address'] = address
        self.response['dob'] = dob
        self.response['phoneNumber'] = phone_number
        self.response['disabilities'] = disabilities

        self.write_json()
