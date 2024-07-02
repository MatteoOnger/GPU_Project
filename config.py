"""
"""

import logging

from dataclasses import dataclass
from types import ModuleType
from typing import Any


logger = logging.getLogger(__name__)


# ---------------------- FUNCTIONS -------------------------
def set_constant(module :ModuleType, name :str, value :Any) -> None:
  """
  """
  if not hasattr(module, name):
    logger.warning(f"{module} has no constant '{name}'")
  setattr(module, name, value)
  return


# ---------------------- CLASSES ---------------------------
@dataclass
class CipherParams():
  """
  """
  name :str
  encrypt :callable
  key_words :int
  plain_words :int
  word_size :int
  word_type :int


@dataclass
class EvoalgParams():
  """
  """
  name :str 
  generate :callable


@dataclass
class ScoringParams():
  """
  """
  name :str 
  evaluate :callable