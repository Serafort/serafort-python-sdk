from typing import Any, Dict, List, Optional


class SerafortError(Exception):
    """Base exception for all Serafort SDK errors."""
    def __init__(self, message: str, code: str = "SERAFORT_ERROR", status: int = 500, details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status
        self.details = details or []

class AuthenticationError(SerafortError):
    """Raised when authentication fails (invalid credentials, expired token, signature mismatch)."""
    def __init__(self, message: str = "Authentication failed.", code: str = "AUTHENTICATION_ERROR", status: int = 401, details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(message, code=code, status=status, details=details)

class RateLimitError(SerafortError):
    """Raised when requests exceed rate limits (HTTP 429)."""
    def __init__(self, message: str = "Rate limit exceeded.", retry_after_seconds: Optional[int] = None, details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(message, code="RATE_LIMIT_EXCEEDED", status=429, details=details)
        self.retry_after_seconds = retry_after_seconds

class ValidationError(SerafortError):
    """Raised when input parameters fail validation."""
    def __init__(self, message: str = "Validation failed.", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(message, code="VALIDATION_ERROR", status=422, details=details)

class NotFoundError(SerafortError):
    """Raised when the requested resource or organization is not found."""
    def __init__(self, message: str = "Resource not found.", code: str = "NOT_FOUND", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(message, code=code, status=404, details=details)

class NetworkError(SerafortError):
    """Raised when network connectivity fails or a timeout occurs."""
    def __init__(self, message: str = "Network connection failed.", cause: Optional[Exception] = None):
        super().__init__(message, code="NETWORK_ERROR", status=0)
        self.__cause__ = cause
