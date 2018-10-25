"""
Enum Extension for improved comparisons
"""
from enum import Enum

# This is because @DynamicClassAttribue isn't exactly @property and pylint doesn't really understand it as the same
# pylint: disable-msg=comparison-with-callable


class AtcaEnum(Enum):
    """
    Overload of standard python enum for some additional convenience features. Assumes closer alignment to C style enums
    where the value is always an integer
    """
    def __str__(self):
        return self.name

    def __eq__(self, other):
        if isinstance(other, str):
            answer = (self.name == other)
        else:
            answer = (self.value == int(other))
        return answer

    def __ne__(self, other):
        if isinstance(other, str):
            answer = (self.name != other)
        else:
            answer = (self.value != int(other))
        return answer

    def __int__(self):
        return int(self.value)


# Make module import * safe - keep at the end of the file
__all__ = ['AtcaEnum']
