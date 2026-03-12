"""
Data Transfer Objects for the KYC bot.

Real modules from memory:
  tg_bot.dto.user (UserDTO)
  tg_bot.dto.service_result (ServiceResult)
  tg_bot.dto.reverify
"""
from tg_bot.dto.user import UserDTO
from tg_bot.dto.service_result import ServiceResult

__all__ = ["UserDTO", "ServiceResult"]
