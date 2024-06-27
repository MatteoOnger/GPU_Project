from enum import Enum


class Scenarios(Enum):
  """
  Enumeration of all the possible attack scenarios.
  """
  SINGLE_KEY  = 0
  """
  The same key is used to encrypt both the inputs of a ciphertext pair.
  """
  RELATED_KEY = 1
  """
  Different keys are used to encrypt the inputs of a ciphertext pair.
  """