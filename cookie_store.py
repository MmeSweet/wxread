
import json
import logging
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

COOKIE_FILE = Path(".wxread-state/cookies.enc")


def get_cipher():
    key = os.getenv("WXREAD_COOKIE_KEY")
    if not key:
        raise RuntimeError("缺少 WXREAD_COOKIE_KEY")
    return Fernet(key.encode("ascii"))


def load_cookies(base_cookies):
    """读取上一次运行保存的 Cookie。"""
    result = dict(base_cookies)

    if not COOKIE_FILE.exists():
        logging.info("没有历史 Cookie，使用初始 Cookie")
        return result

    try:
        encrypted = COOKIE_FILE.read_bytes()
        saved = json.loads(
            get_cipher().decrypt(encrypted).decode("utf-8")
        )

        if not isinstance(saved, dict):
            raise ValueError("Cookie 数据格式不正确")

        if not all(
            isinstance(k, str) and isinstance(v, str)
            for k, v in saved.items()
        ):
            raise ValueError("Cookie 字段格式不正确")

        result.update(saved)
        logging.info("已恢复上次保存的 Cookie")
        return result

    except (InvalidToken, ValueError, UnicodeError) as exc:
        raise RuntimeError(
            "Cookie 缓存解密失败，请检查加密密钥"
        ) from exc


def save_cookies(cookies):
    """加密保存 Cookie，供下次 Actions 使用。"""
    cipher = get_cipher()

    COOKIE_FILE.parent.mkdir(
        parents=True, exist_ok=True
    )

    encrypted = cipher.encrypt(
        json.dumps(
            cookies, ensure_ascii=False
        ).encode("utf-8")
    )

    temp = COOKIE_FILE.with_suffix(".tmp")
    temp.write_bytes(encrypted)
    os.chmod(temp, 0o600)
    os.replace(temp, COOKIE_FILE)

    logging.info("Cookie 已加密保存")
