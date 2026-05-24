from prompt_toolkit import PromptSession


class Interpreter:
    def __init__(self):
        self._session = PromptSession()
        self.ssid = None

    def run(self):
        while True:
            try:
                user_input = self._session.prompt(f"[{self.ssid}]> ")
                print(user_input)
            except (KeyboardInterrupt, EOFError):
                break


if __name__ == "__main__":
    i = Interpreter()
    i.run()
