from .Symbol import Symbol
from .Terminal import Terminal

class NonTerminal(Symbol):
    def convertToTerminal(self):
        return Terminal(self.name)