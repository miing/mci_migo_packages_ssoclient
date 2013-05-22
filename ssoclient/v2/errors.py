from ssoclient.v2.http import ApiException


# 400
class InvalidData(ApiException):
    error_code = "INVALID_DATA"


# 401
class CaptchaRequired(ApiException):
    error_code = "CAPTCHA_REQUIRED"


class InvalidCredentials(ApiException):
    error_code = "INVALID_CREDENTIALS"


class TwoFactorRequired(ApiException):
    error_code = "TWOFACTOR_REQUIRED"


# 403
class AccountSuspended(ApiException):
    error_code = "ACCOUNT_SUSPENDED"


class AccountDeactivated(ApiException):
    error_code = "ACCOUNT_DEACTIVATED"


class EmailInvalidated(ApiException):
    error_code = "EMAIL_INVALIDATED"


class CanNotResetPassword(ApiException):
    error_code = "CAN_NOT_RESET_PASSWORD"


class CaptchaFailure(ApiException):
    error_code = "CAPTCHA_FAILURE"


class TooManyTokens(ApiException):
    error_code = "TOO_MANY_TOKENS"


class TwoFactorFailure(ApiException):
    error_code = "TWOFACTOR_FAILURE"


# 404
class ResourceNotFound(ApiException):
    error_code = "RESOURCE_NOT_FOUND"


# 409
class AlreadyRegistered(ApiException):
    error_code = "ALREADY_REGISTERED"
