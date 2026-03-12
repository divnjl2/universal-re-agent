"""
ServiceResult — generic result wrapper for service operations.

From memory:
  ServiceResult(success: 'bool', data: 'Optional[T]' = None, error: 'Optional[ServiceError]' = None)
  ServiceResult.ok
  ServiceResult.fail
  ServiceResult.__eq__
  ServiceResult.__init__
  ServiceResult.__repr__
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Generic, Optional, TypeVar

T = TypeVar("T")


@dataclass
class ServiceError:
    """Error detail from a service operation."""
    code: str = "UNKNOWN"
    message: str = ""


@dataclass
class ServiceResult(Generic[T]):
    """
    Generic result wrapper for service calls.

    Usage:
        result = ServiceResult.ok(data=some_value)
        result = ServiceResult.fail(error=ServiceError(code="NOT_FOUND", message="..."))
    """
    success: bool = False
    data: Optional[T] = None
    error: Optional[ServiceError] = None

    @classmethod
    def ok(cls, data: T = None) -> ServiceResult[T]:
        """Create a successful result."""
        return cls(success=True, data=data)

    @classmethod
    def fail(cls, error: ServiceError | None = None, message: str = "") -> ServiceResult[T]:
        """Create a failed result."""
        if error is None:
            error = ServiceError(message=message)
        return cls(success=False, error=error)

    def __repr__(self) -> str:
        if self.success:
            return f"ServiceResult(ok, data={self.data!r})"
        return f"ServiceResult(fail, error={self.error!r})"
