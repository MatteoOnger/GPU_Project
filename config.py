"""
Helper functions and classes to configure the execution.
"""

import logging

from dataclasses import dataclass
from types import ModuleType
from typing import Any


logger = logging.getLogger(__name__)


# ---------------------- FUNCTIONS -------------------------
def set_constant(module :ModuleType, name :str, value :Any) -> None:
  """
  Set the given constant of the given module to the given value.

  Parameters
  ----------
  ``module``: ModuleType
    The module to set the constant on.
  ``name``: str
    The name of the constant to set.
  ``value``: Any
    The value to set the constant to.
  """
  if not hasattr(module, name):
    logger.warning(f"{module} has no constant '{name}'")
  setattr(module, name, value)
  return


# ---------------------- CLASSES ---------------------------
@dataclass
class CipherParams():
  """
  Dataclass containing parameters related to the chosen cipher. 
  """
  name :str
  """
  Cipher name.
  """
  encrypt_func :callable
  """
  Function to encrypt data.
  """
  key_size :int
  """
  Key size in number of words.
  """
  plain_size :int
  """
  Plaintext size in number of words.
  """
  word_size :int
  """
  Number of bits per word.
  """
  word_type :type
  """
  Numpy or Cupy type of the words.
  """


@dataclass
class EvoalgParams():
  """
  Dataclass containing parameters related to the chosen evolutionary algo. 
  """
  name :str
  """
  Name of the algorithm.
  """
  evolve_func :callable
  """
  Function to call the algorithm.
  """


@dataclass
class FitnessParams():
  """
  Dataclass containing parameters related to the chosen fitness function. 
  """
  name :str
  """
  Name of the function.
  """
  evaluate_func :callable
  """
  Function to call to evaluate the differences.
  """