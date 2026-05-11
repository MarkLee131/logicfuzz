from abc import ABC, abstractmethod
from typing import List, Set, Dict, Tuple, Optional

from . import Statement, Type, Variable, Buffer

class BuffInit(Statement):
    buffer: Buffer

    def __init__(self, buffer):
        super().__init__()
        self.buffer = buffer
        # TODO: map buffer and input
        # self.buffer_map = {}

    # See BuffDecl.__hash__: same upstream-shared bug fixed in adapter.
    def __hash__(self):
        return hash(self.buffer.get_token() + str(self.__class__.__name__))

    def __str__(self):
        return f"{self.__class__.__name__}(name={self.buffer.get_token()})"

    def get_buffer(self):
        return self.buffer