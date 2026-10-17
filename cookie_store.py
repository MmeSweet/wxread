
import hashlib
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


def get_curl_fingerprint():
    """
    为当前 WXREAD_CURL_BASH 生成指纹。
    用于判断用户是否重新抓取了登录凭证。
    """
    curl = os.getenv("WXREAD_CURL_BASH")

    if not curl:
        raise RuntimeError("缺少 WXREAD_CURL_BASH")

    return hashlib.sha256( 
        curl.encode("utf-8")
    ).hexdigest()


def load_cookies(base_cookies):
    """
    加载 Cookie：
    1. 首次运行使用 cURL 中的 Cookie
    2. cURL 未变化时使用续期缓存
    3. cURL 改变时自动丢弃旧缓存
    """
    result = dict(base_cookies)

    if not COOKIE_FILE.exists():
        logging.info("没有历史 Cookie，使用初始 cURL")
        return result

    try:
        encrypted = COOKIE_FILE.read_bytes()

        saved = json.loads(
            get_cipher().decrypt(encrypted).decode("utf-8")
        )

        if not isinstance(saved, dict):
            raise ValueError("缓存数据格式错误")

        # 旧版本没有指纹，不继续使用
        if "fingerprint" not in saved:
            logging.info(
                "发现旧格式 Cookie 缓存，"
                "使用当前 cURL 重新初始化"
            )
            return result

        current_fingerprint = get_curl_fingerprint()

        if saved["fingerprint"] != current_fingerprint:
            logging.info(
                "检测到 WXREAD_CURL_BASH 已更新，"
                "自动忽略旧 Cookie 缓存"
            )
            return result

        saved_cookies = saved.get("cookies")

        if not isinstance(saved_cookies, dict):
            raise ValueError("缓存 Cookie 格式错误")

        if not all(
            isinstance(k, str) and isinstance(v, str)
            for k, v in saved_cookies.items()
        ):
            raise ValueError("缓存 Cookie 字段类型错误")

        result.update(saved_cookies)

        logging.info(
            "已恢复上次保存的 Cookie，"
            "当前 cURL 未变化"
        )

        return result

    except (InvalidToken, ValueError, UnicodeError) as exc:
        raise RuntimeError(
            "Cookie 缓存解密或解析失败，"
            "请检查 WXREAD_COOKIE_KEY"
        ) from exc


def save_cookies(cookies):
    """
    同时加密保存：
    - 当前 cURL 的指纹
    - 最新 Cookie

    不保存原始 cURL。
    """
    cipher = get_cipher()

    COOKIE_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    payload = {
        "fingerprint": get_curl_fingerprint(),
        "cookies": dict(cookies)
    }

    encrypted = cipher.encrypt(
        json.dumps(
            payload,
            ensure_ascii=False
        ).encode("utf-8")
    )

    temp = COOKIE_FILE.with_suffix(".tmp")

    temp.write_bytes(encrypted)
    os.chmod(temp, 0o600)

    os.replace(temp, COOKIE_FILE)

    logging.info(
        "Cookie 已加密保存，"
        "并记录当前 cURL 指纹"
    )
