import math
import time

import pyotp


def get_counter(window_seconds: int = 60) -> int:
    return math.floor(time.time() / window_seconds)


def generate_totp(secret: str, window_seconds: int = 60) -> tuple[str, int]:
    totp = pyotp.TOTP(secret, interval=window_seconds, digits=6)
    counter = get_counter(window_seconds)
    code = totp.now()
    return code, counter


def verify_totp(secret: str, code: str, window_seconds: int = 60, valid_window: int = 1) -> tuple[bool, int | None]:
    totp = pyotp.TOTP(secret, interval=window_seconds, digits=6)
    c = get_counter(window_seconds)
    for offset in range(-valid_window, valid_window + 1):
        expected = totp.generate_otp(c + offset)
        if expected == code:
            return True, c + offset
    return False, None


def check_replay(src_ip: str, counter: int, replay_cache: dict[str, int], window_seconds: int = 60) -> bool:
    key = src_ip
    if key in replay_cache:
        last_counter = replay_cache[key]
        max_drift = (2 * window_seconds) // window_seconds
        if abs(counter - last_counter) < max_drift:
            return True
    replay_cache[key] = counter
    return False
