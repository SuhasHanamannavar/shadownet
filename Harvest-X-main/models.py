from enum import Enum

class AttackerType(Enum):
    BOT = "bot"
    HUMAN = "human"
    ADVANCED = "advanced"

class SystemPersona(Enum):
    LINUX_SERVER = "linux_server"
    IOT_DEVICE = "iot_device"
    ENTERPRISE_SERVER = "enterprise_server"