"""Read the known LynkCo 4.3.x fixed KeyVault slots from an APK.

Offsets are valid only for the verified ARM64 library below. Unknown layouts
must not silently reuse them or fall back to a debugger-based extraction.
"""

import re
import struct
import os
import zipfile


LIBRARY = "lib/arm64-v8a/libkeyvault.so"
TABLE_OFFSET = 0x1130
TABLE_COUNT_OFFSET = 0x1320
ENTRY_SIZE = 0x7C


class UnsupportedKeyVault(ValueError):
    """The APK contains a KeyVault layout not recognized by this extractor."""


def read_library(apk_path):
    """Return the ARM64 library, or None only when the APK has no KeyVault."""
    try:
        with zipfile.ZipFile(apk_path) as archive:
            entries = [name for name in archive.namelist()
                       if name.endswith("/libkeyvault.so")]
            if not entries:
                return None
            if LIBRARY not in entries:
                raise UnsupportedKeyVault("APK 含 KeyVault，但缺少受支持的 ARM64 库")
            return archive.read(LIBRARY)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise UnsupportedKeyVault("APK 无法读取或已损坏") from exc


def extract(apk_path, app_key=None, app_code=None):
    """Return (app_key, app_secret) or None for APKs without KeyVault.

    No recovered secret is printed here. The caller controls output and storage.
    """
    library = read_library(apk_path)
    if library is None:
        return None
    count = struct.unpack_from("<I", library, TABLE_COUNT_OFFSET)[0]
    if count != 4 or TABLE_OFFSET + count * ENTRY_SIZE != TABLE_COUNT_OFFSET:
        raise UnsupportedKeyVault("KeyVault 固定槽位数量或位置不符")

    records = []
    for index in range(count):
        entry = TABLE_OFFSET + index * ENTRY_SIZE
        slot = struct.unpack_from("<I", library, entry)[0]
        code_length = struct.unpack_from("<I", library, entry + 0x1C)[0]
        key_length = struct.unpack_from("<I", library, entry + 0x34)[0]
        secret_length = struct.unpack_from("<I", library, entry + 0x78)[0]
        if not (slot == index + 1 and 0 < code_length <= 11
                and 0 < key_length <= 9 and secret_length == 32):
            raise UnsupportedKeyVault("KeyVault 固定槽位元数据不符")
        code = bytes(library[entry + 4 + i] ^ library[entry + 0xF + i]
                     for i in range(code_length))
        key = bytes(library[entry + 0x20 + i] ^ library[entry + 0x29 + i]
                    for i in range(key_length))
        secret = bytes(library[entry + 0x38 + i] ^ library[entry + 0x58 + i]
                       for i in range(secret_length))
        if not re.fullmatch(rb"[0-9A-Za-z]{32}", secret):
            raise UnsupportedKeyVault("KeyVault 命中槽位的密钥格式异常")
        records.append((code.decode("ascii"), key.decode("ascii"), secret.decode("ascii")))

    app_key = app_key or os.environ.get("LYNKCO_APP_KEY")
    app_code = app_code or os.environ.get("LYNKCO_APP_CODE")
    if app_key is None and app_code is None:
        # The first record is the production slot in the verified 4.3.x layout.
        _, app_key, secret = records[0]
        return app_key, secret
    if app_key is not None and not re.fullmatch(r"[0-9]{9}", app_key):
        raise ValueError("appKey 应为 9 位数字")
    if app_code is not None and not app_code.isascii():
        raise ValueError("appCode 应为 ASCII 字符串")
    matches = {(key, secret) for code, key, secret in records
               if (app_key is None or key == app_key)
               and (app_code is None or code == app_code)}
    if len(matches) != 1:
        raise UnsupportedKeyVault("KeyVault 槽位未唯一匹配选择条件")
    return matches.pop()
