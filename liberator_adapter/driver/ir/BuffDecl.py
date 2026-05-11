from abc import ABC, abstractmethod
from typing import List, Set, Dict, Tuple, Optional

from . import Statement, Type, Variable, Buffer

class BuffDecl(Statement):
    buffer: Buffer

    def __init__(self, buffer):
        super().__init__()
        self.buffer = buffer
        # TODO: map buffer and input
        # self.buffer_map = {}

    # Hash by the underlying buffer's token + class name. Upstream
    # Liberator's __hash__ referenced ``self.token`` directly, which
    # this class never sets — any caller hashing a BuffDecl hit
    # AttributeError. Latent because LFBackendDriver was dead and
    # Statements aren't put in sets on the live render path.
    def __hash__(self):
        return hash(self.buffer.get_token() + str(self.__class__.__name__))

    def __str__(self):
        return f"{self.__class__.__name__}(name={self.buffer.get_token()})"

    def get_buffer(self):
        return self.buffer