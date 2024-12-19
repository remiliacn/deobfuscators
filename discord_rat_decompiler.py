from re import findall
from subprocess import run, PIPE
from sys import argv, platform

from loguru import logger

from constants.general import INVALID_TOKEN
from constants.regex import DISCORD_TOKEN_MATCHER
from discord_token_validator import validate


def extract_result_using_monodis(exe_path) -> str:
    result = run(['monodis', exe_path], stdout=PIPE, stderr=PIPE, text=True)

    bot_token = findall(DISCORD_TOKEN_MATCHER, result.stdout)
    if bot_token:
        actual_token = bot_token[0]
        logger.success(f"Found bot token: {actual_token}")
        if validate(actual_token, True):
            return actual_token

    return INVALID_TOKEN


def discord_rat_decompiler(exe_path: str) -> str:
    logger.info('Extracting valuable data from C# executable')

    strings_extraction = extract_result_using_monodis(exe_path)
    return strings_extraction


if __name__ == '__main__':
    if platform == 'win32':
        logger.error('Windows decompiling is currently not supported.')
        exit(1)

    logger.success(f'Found result: {discord_rat_decompiler(argv[1])}')
