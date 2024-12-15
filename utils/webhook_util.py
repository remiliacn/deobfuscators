from copy import deepcopy
from typing import List, Union

from httpx import delete, get
from loguru import logger


def validate_and_delete_webhook(webhook: str) -> bool:
    if not webhook:
        return False

    if 'http' not in webhook:
        return False

    webhook_status_code = get(webhook).status_code
    logger.debug(f'Webhook status code: {webhook_status_code}')
    if webhook_status_code <= 205:
        logger.info(f"webhook: {webhook} is valid!")
        result = delete(webhook, headers={"Content-Type": "application/json"})
        logger.success(
            f"Webhook {webhook} is retrieved successfully and deleted!! {result.status_code}"
        )

        return True

    return False


def validate_webhooks(webhooks_temp: List[Union[tuple, str]]) -> List[str]:
    webhooks = deepcopy(webhooks_temp)
    for w in webhooks_temp:
        if isinstance(w, tuple):
            web = w[0]
            webhooks.remove(w)
            webhooks.append(web)
        else:
            web = w

        if not validate_and_delete_webhook(web):
            webhooks.remove(web)
            logger.warning(f"Webhook: {web} is not valid.")
        else:
            logger.info(f"Webhook: {web} is valid.")

    return webhooks
