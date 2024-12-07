"""
Discord token validator

Author: @remiliacn
"""
import httpx
from time import sleep
from loguru import logger

def validate(token: str, is_bot: bool) -> bool:
    headers = {
        "Authorization": token.strip() if not is_bot else f'Bot {token.strip()}'
    }
    response = httpx.get("https://discord.com/api/v10/users/@me", headers=headers)

    sleep(2)

    if response.status_code != 200 and response.status_code != 401:
        logger.warning(f'Received unknown status code {response.status_code}')

    return response.status_code == 200


if __name__ == '__main__':
    with open('tokens.txt') as file:
        for token in file.readlines():
            if validate(token):
                logger.success(token)
            else:
                logger.error(token)