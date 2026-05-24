from enum import Enum


class ConnectionStatus(Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"


class Wifi:
    def __init__(self) -> None:
        self.ssid = None
        self.connection_status = ConnectionStatus.DISCONNECTED

    def __str__(self) -> str:
        if self.ssid:
            return f"{self.ssid}({self.connection_status})"
        else:
            return "None"
