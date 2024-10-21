class PushbunnyAuthException(Exception):
    """Base exception class for Pushbunny Auth"""
    def __init__(self, message, status_code=400):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)

class InvalidCredentialsException(PushbunnyAuthException):
    """Exception raised for invalid credentials"""
    def __init__(self, message="Invalid credentials"):
        super().__init__(message, status_code=401)

class UnauthorizedException(PushbunnyAuthException):
    """Exception raised for unauthorized access"""
    def __init__(self, message="Unauthorized access"):
        super().__init__(message, status_code=403)

class NotFoundException(PushbunnyAuthException):
    """Exception raised for not found resources"""
    def __init__(self, message="Resource not found"):
        super().__init__(message, status_code=404)

class ServerErrorException(PushbunnyAuthException):
    """Exception raised for server errors"""
    def __init__(self, message="Internal server error"):
        super().__init__(message, status_code=500)
