"""
Discord token validator

Author: @remiliacn
"""
from base64 import b64decode
from re import match
from sys import argv

import httpx
from loguru import logger

from constants.regex import DISCORD_TOKEN_MATCHER


def validate(token: str, is_bot: bool) -> bool:
    if not token:
        return False

    if not match(DISCORD_TOKEN_MATCHER, token):
        logger.warning('Invalid discord token')
        return False

    headers = {
        "Authorization": token.strip() if not is_bot else f'Bot {token.strip()}'
    }
    response = httpx.get("https://discord.com/api/v10/users/@me", headers=headers)
    user_id = token.split(".")[0]
    logger.info(
        f'Token user id: {b64decode(user_id + '=' * (-len(user_id) % 4)).decode("utf-8")},'
        f' status code: {response.status_code}')

    if response.status_code != 200 and response.status_code != 401:
        logger.warning(f'Received unknown status code {response.status_code}')

    return response.status_code == 200


if __name__ == '__main__':
    if len(argv) == 2:
        logger.info(f'Is token valid: {validate(argv[1], True)}')
