#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import json
import uuid
import logging
import hashlib
import datetime

from optparse import OptionParser
from collections import OrderedDict
from http.server import HTTPServer, BaseHTTPRequestHandler

from scoring import get_interests, get_score

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class AutoStorage:
    def __init__(self, *args, **kwargs):
        self.storage_name = None

    def __get__(self, instance, owner):
        if instance is None:
            return self
        return getattr(self, self.storage_name, None)

    def __set__(self, instance, value):
        setattr(self, self.storage_name, value)


class Field(abc.ABC, AutoStorage):
    def __init__(self, required=False, nullable=False):
        super().__init__()
        self.required = required
        self.nullable = nullable

    def __set__(self, instance, value):
        if value is None and self.required:
            raise ValueError('required value is missing')
        if not value and not self.nullable:
            raise ValueError('value can\'t be empty')
        value = value and self.validate(instance, value)
        super().__set__(instance, value)

    @abc.abstractmethod
    def validate(self, instance, value):
        """ validate value before assignment """


class CharField(Field):
    def validate(self, instance, value):
        if not isinstance(value, str):
            raise ValueError(f'value must be a string or null, got {value!r}')
        return value.strip()


class ArgumentsField(Field):
    def validate(self, instance, value):
        if not isinstance(value, dict):
            raise ValueError(f'Arguments must be a mapping, got {value!r}')
        return value


class EmailField(CharField):
    def validate(self, instance, value):
        if not isinstance(value, str):
            raise ValueError('invalid email')
        if '@' not in value:
            raise ValueError('invalid email')
        return value


class PhoneField(Field):
    def validate(self, instance, value):
        if not isinstance(value, (str, int)):
            raise ValueError(f'Phone value must be a string or number, got {value!r}')
        value = str(value)
        if not len(value) == 11:
            raise ValueError(f'The phone must consist of 11 digits, got {len(value)!r}')
        if not value.startswith('7'):
            raise ValueError(f'The phone must begin with the number, but starts with {value[0]}')
        return value


class DateField(Field):
    def validate(self, instance, value):
        try:
            datetime.datetime.strptime(value, '%d.%m.%Y')
        except TypeError as e:
            raise ValueError(f'Date must be a string, got {value!r}')
        return value


class BirthDayField(DateField):
    def validate(self, instance, value):
        value = super().validate(instance, value)
        date = datetime.datetime.strptime(value, '%d.%m.%Y')
        too_old = datetime.timedelta(70*365)
        if datetime.datetime.now() - date > too_old:
            raise ValueError('error')
        return value


class GenderField(Field):
    def validate(self, instance, value):
        if GENDERS.get(value) is None:
            raise ValueError('error')
        return value


class ClientIDsField(Field):
    def validate(self, instance, value):
        if not isinstance(value, list):
            raise ValueError(f'value must be a list, got {value!r}')
        if not all(isinstance(n, int) for n in value):
            raise ValueError(f'value must be a list of integers')
        if not value:
            raise ValueError(f'value must be a not empty, got {value!r}')
        return value


class RequestMeta(abc.ABC, type):
    @classmethod
    def __prepare__(metacls, name, bases):
        return OrderedDict()

    def __init__(cls, name, bases, attr_dict):
        super().__init__(name, bases, attr_dict)
        cls._field_names = []
        for key, attr in attr_dict.items():
            if isinstance(attr, Field):
                attr.storage_name = key
                cls._field_names.append(key)


class Request(metaclass=RequestMeta):
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.is_valid, self.error = self.validate()

    @classmethod
    def fields_names(cls):
        for field in cls._field_names:
            yield field

    def validate(self):
        for field in self.fields_names():
            value = self.kwargs.get(field)
            try:
                setattr(self, field, value)
            except ValueError as e:
                return False, str(e)
        return True, ''


class Method(Request):
    def response(self, store, ctx):
        return self.make_response(store, ctx)

    @abc.abstractmethod
    def make_response(self, store, ctx):
        """ make a response """


class ClientsInterestsRequest(Method):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def make_response(self, store, ctx):
        ctx['nclients'] = len(self.client_ids)
        return {cid: get_interests(store, cid) for cid in self.client_ids}


class OnlineScoreRequest(Method):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def validate(self):
        pairs = [('phone', 'email'), ('first name', 'last name'), ('gender', 'birthday')]
        for left, right in pairs:
            if self.kwargs.get(left) and self.kwargs.get(right):
                return super().validate()
        return False, 'too few values'

    def make_response(self, store, ctx):
        kwargs = {
            'phone': self.phone, 'email': self.email,
            'birthday': self.birthday, 'gender': self.gender,
            'first_name': self.first_name, 'last_name': self.last_name
        }
        score = 42 if ctx.get('is_admin') else get_score(store, **kwargs)
        ctx['has'] = [k for k, v in self.kwargs.items() if v]
        return {'score': score}


class MethodRequest(Request):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        data = datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT
        digest = hashlib.sha512(data.encode('utf8')).hexdigest()
    else:
        data = request.account + request.login + SALT
        digest = hashlib.sha512(data.encode('utf8')).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    methods = {'online_score': OnlineScoreRequest, 'clients_interests': ClientsInterestsRequest}
    data = MethodRequest(**request.get('body'))
    if not request.get('body'):
        return 'empty request', INVALID_REQUEST
    if not data.is_valid:
        return data.error, INVALID_REQUEST
    if not check_auth(data):
        return 'forbidden', FORBIDDEN
    arguments = data.arguments or {}
    method = methods.get(data.method)(**arguments)
    if not method.is_valid:
        return method.error, INVALID_REQUEST
    ctx['is_admin'] = data.is_admin
    return method.response(store, ctx), OK


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode('utf8'))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
