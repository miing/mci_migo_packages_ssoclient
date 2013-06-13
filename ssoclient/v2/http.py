import functools
import json

import requests

JSON_MIME_TYPE = 'application/json'


class UnexpectedApiError(Exception):
    pass


class ServerError(UnexpectedApiError):
    """An unexpected 5xx response"""
    def __init__(self, response, msg="", json=None):
        self.response = response
        self.json_body = json
        super(ServerError, self).__init__(
            "%s : %s - %s" % (response.status_code, response.text, msg)
        )


class ClientError(UnexpectedApiError):
    """An unexpected 4xx response"""
    def __init__(self, response, msg="", json=None):
        self.response = response
        self.json_body = json
        super(ClientError, self).__init__(
            "%s : %s - %s" % (response.status_code, response.text, msg)
        )


class ApiException(Exception):
    """An expected/understood 4xx or 5xx response.

    Parses the standard api error reponse format.
    """
    def __init__(self, response, body=None, msg=None):
        body = body or {}
        self.response = response
        self.body = body
        self.error_message = body.get('message')
        self.extra = body.get('extra', {})
        if msg is None:
            # code *should* be the same as the error_code attribute
            # but won't be for raising an ApiException directly instead
            # of a subclass - so still fetch it from the payload body
            code = body.get('code')
            msg = "%s: %s" % (response.status_code, code)
        super(ApiException, self).__init__(msg)


def api_exception(exception_class):
    """Register an exception to be raised

    Parse the response from the decorated function, and if it's 400,
    look for the registered ApiException subclass to raise, else raise
    a generic ApiException.
    """

    assert issubclass(exception_class, ApiException)
    code = exception_class.error_code
    assert code, "ApiException subclass requires a valid error_code attribute"

    def decorator(func):
        if hasattr(func, '_api_exceptions'):
            func._api_exceptions[code] = exception_class
            return func

        api_exceptions = {code: exception_class}

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            response = func(*args, **kwargs)
            json_body = {}
            try:
                json_body = response.json()
            except ValueError:
                # simplejson raises JSONDecodeError for invalid json
                # json raises ValueError. JSONDecodeError is a subclass
                # of ValueError - so this catches either.
                pass

            if response.status_code >= 400:
                code = json_body.get('code')
                if code in api_exceptions:
                    exception_class = api_exceptions[code]
                    raise exception_class(response, json_body)
                elif code:
                    msg = "Unknown error code '%s' in response" % code
                else:
                    msg = "No error code in response"
                if response.status_code < 500:
                    exc = ClientError
                else:
                    exc = ServerError
                raise exc(response, msg, json_body)

            return response

        wrapper._api_exceptions = api_exceptions
        return wrapper
    return decorator


class ApiSession(requests.Session):
    """An SSO api specfic Session

    Adds support for a url endpoint, 500 exceptions, and JSON request body
    handling.
    """

    def __init__(self, endpoint):
        super(ApiSession, self).__init__()
        self.endpoint = endpoint.rstrip('/') + '/'
        # sent with every request
        self.headers['Accept'] = JSON_MIME_TYPE

    def request(self, method, url, **kwargs):
        if 'headers' not in kwargs:
            kwargs['headers'] = {}
        if 'data' in kwargs:
            kwargs['data'] = json.dumps(kwargs['data'])
            kwargs['headers']['Content-Type'] = JSON_MIME_TYPE
        url = self.endpoint + url.lstrip('/')
        response = super(ApiSession, self).request(method, url, **kwargs)
        return response
