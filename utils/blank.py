"""
Blank grabber helper utility.

Source from: https://github.com/TaxMachine/Grabbers-Deobfuscator/blob/main/utils/deobfuscation.py

License: WTFPL (https://github.com/TaxMachine/Grabbers-Deobfuscator/issues/20)

Author: @TaxMachine, @Remiliacn (modified for amnesia use case.)
"""

from base64 import b64decode
from binascii import Error
from codecs import decode
from dataclasses import dataclass
from lzma import decompress
from re import M, MULTILINE, findall, search, sub
from string import printable
from typing import List

from loguru import logger

from constants.regex import (
    TELEGRAM_REGEX,
    TELEGRAM_REGEX_BASE64,
    WEBHOOK_REGEX,
    WEBHOOK_REGEX_BASE64,
)
from utils.webhook_util import validate_webhooks


@dataclass
class BlankStage3Obj:
    first: str
    second: str
    third: str
    fourth: str


def blank_stage3(assembly: bytes) -> BlankStage3Obj:
    bytestr = b"\xfd7zXZ\x00\x00" + assembly.split(b"\xfd7zXZ\x00\x00")[1]
    decompressed = decompress(bytestr)
    sanitized = decompressed.decode().replace(";", "\n")
    sanitized = sub(r"^__import__.*", "", sanitized, flags=M)
    return BlankStage3Obj(
        search(r'^____="(.*)"$', sanitized, MULTILINE).group(1),
        search(r'^_____="(.*)"$', sanitized, MULTILINE).group(1),
        search(r'^______="(.*)"$', sanitized, MULTILINE).group(1),
        search(r'^_______="(.*)"$', sanitized, MULTILINE).group(1),
    )


def base64_decode_then_filter(encoded_string: List[str]) -> List[str]:
    cleaned_strings = []
    for x in encoded_string:
        try:
            uncleaned_decoded_string = b64decode(x).decode("utf-8", errors="ignore")
            unprintable_index = len(uncleaned_decoded_string)
            for i, value in enumerate(uncleaned_decoded_string):
                if value not in printable:
                    unprintable_index = i
                    break

            cleaned_string = uncleaned_decoded_string[:unprintable_index]
            cleaned_strings.append(cleaned_string)
        except Error:
            pass

    return cleaned_strings


def blank_stage4(stage3_obj: BlankStage3Obj) -> List[str]:
    try:
        unrot = decode(stage3_obj.first, "rot13")
        pythonbytes = b64decode(
            unrot + stage3_obj.second + stage3_obj.third[::-1] + stage3_obj.fourth
        )
        with open("dump.bin", "wb") as f:
            f.write(pythonbytes)
    except Exception as e:
        print(e)
        raise Exception(e)
    strings = decode(pythonbytes, "ascii", errors="ignore").replace("\x18", "")

    webhook64 = findall(WEBHOOK_REGEX_BASE64, strings)
    webhook = findall(WEBHOOK_REGEX, strings)
    telegram64 = findall(TELEGRAM_REGEX_BASE64, strings)
    telegram = findall(TELEGRAM_REGEX, strings)

    webhook_to_list = []

    if webhook:
        for ww in webhook:
            if isinstance(ww, str):
                webhook_to_list.append(ww)
            elif isinstance(ww, tuple):
                webhook_to_list = [x for x in ww if x]

    if telegram:
        telegram_to_list = []
        for ww in telegram:
            if isinstance(ww, str):
                telegram_to_list.append(ww)
            elif isinstance(ww, tuple):
                telegram_to_list = [x for x in ww if x]

        telegram = telegram_to_list

    if webhook64:
        webhook64 = base64_decode_then_filter(webhook64)
    if telegram64:
        telegram64 = base64_decode_then_filter(telegram64)
        telegram64 = [x.replace("$", " || ") for x in telegram64]
    if webhook or webhook64 or telegram or telegram64:
        logger.success(f"We got something!!")

    valid_webhooks = []
    if webhook or webhook64:
        webhooks = webhook + webhook64
        valid_webhooks = validate_webhooks(webhooks)

    return valid_webhooks + telegram + telegram64
