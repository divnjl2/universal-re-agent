"""
Pydantic schemas for the FastAPI application.
"""

from .base import (
    StatusResponse,
    ErrorResponse,
    BulkOperationResult,
    PaginatedResponse,
    DatabaseIdList,
)
from .database import (
    AccountCreate,
    AccountUpdate,
    AccountResponse,
    AccountListResponse,
    EmailCreate,
    EmailResponse,
    ImportAccountsRequest,
)
