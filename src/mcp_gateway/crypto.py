import base64
import hashlib
import json

from cryptography.fernet import Fernet

from mcp_gateway.settings import Settings


def _key_from_settings(settings: Settings) -> bytes:
    if settings.encryption_key:
        return settings.encryption_key.encode("utf-8")
    digest = hashlib.sha256(settings.secret_key.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_config(config: dict, settings: Settings) -> str:
    payload = json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return Fernet(_key_from_settings(settings)).encrypt(payload).decode("utf-8")


def decrypt_config(encrypted: str, settings: Settings) -> dict:
    raw = Fernet(_key_from_settings(settings)).decrypt(encrypted.encode("utf-8"))
    return json.loads(raw.decode("utf-8"))
