from prompt_toolkit import PromptSession
from .wifi import Wifi


class Interpreter:
    def __init__(self):
        self._session = PromptSession()
        self._wifi = Wifi()

    def repl(self):
        while True:
            try:
                user_input = self._session.prompt(f"[{self._wifi}]> ")
                print(user_input)
            except (KeyboardInterrupt, EOFError):
                break
