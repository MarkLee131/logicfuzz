from . import Symbol, Terminal

class NonTerminal(Symbol):
    def convertToTerminal(self):
        return Terminal(self.name)