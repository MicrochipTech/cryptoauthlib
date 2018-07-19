from enum import Enum


class AtcaEnum(int, Enum):
    """
    Overload of standard python enum for some additional convenience features. Assumes closer alignment to C style enums
    where the value is always an integer
    """
    def __str__(self):
        return self.name

    def __eq__(self, other):
        if isinstance(other, int):
            return self.value == other
        elif isinstance(other, str):
            return self.name == other
        else:
            return super().__eq__(other)

    def __ne__(self, other):
        if isinstance(other, int):
            return self.value != other
        elif isinstance(other, str):
            return self.name != other
        else:
            return super().__eq__(other)

    def __int__(self):
        return int(self.value)