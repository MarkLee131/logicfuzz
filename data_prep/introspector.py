"""Slim Fuzz Introspector client.

Single retained endpoint: ``/api/all-functions`` — used to fetch the
per-function ``code_coverage`` value that powers L5 coverage-aware filtering
in :mod:`src.context.data_context`. That is the only OSS-Fuzz-specific input
LogicFuzz still pulls from FI.

All other helpers (function source, headers, oracles, benchmark generation,
language stats, target selection) were dropped together with the local
fuzz-introspector dependency.
"""

import logging
import random
import time
from typing import Optional, TypeVar
from urllib.parse import urlencode

import requests

logger = logging.getLogger(__name__)

T = TypeVar('T', str, list, dict, int)

TIMEOUT = 120
MAX_RETRY = 5

DEFAULT_INTROSPECTOR_ENDPOINT = 'https://introspector.oss-fuzz.com/api'
INTROSPECTOR_ENDPOINT = DEFAULT_INTROSPECTOR_ENDPOINT
INTROSPECTOR_ALL_FUNCTIONS = f'{INTROSPECTOR_ENDPOINT}/all-functions'


def set_introspector_endpoints(endpoint: str) -> None:
  """Override the FI base URL (e.g. point at a private mirror)."""
  global INTROSPECTOR_ENDPOINT, INTROSPECTOR_ALL_FUNCTIONS
  INTROSPECTOR_ENDPOINT = endpoint
  INTROSPECTOR_ALL_FUNCTIONS = f'{INTROSPECTOR_ENDPOINT}/all-functions'


def _construct_url(api: str, params: dict) -> str:
  return api + '?' + urlencode(params)


def _query_introspector(api: str, params: dict) -> Optional[requests.Response]:
  logger.info('Querying FuzzIntrospector API: %s', api)
  for attempt_num in range(1, MAX_RETRY + 1):
    try:
      resp = requests.get(api, params, timeout=TIMEOUT)
      if not resp.ok:
        logger.error('Failed to get data from FI: %s\n%s', resp.url,
                     resp.content.decode('utf-8', errors='replace').strip())
        return None
      return resp
    except requests.exceptions.Timeout as err:
      if attempt_num == MAX_RETRY:
        logger.error('FI timeout, max retry exceeded: %s (%s)',
                     _construct_url(api, params), err)
        return None
      delay = 5 * 2**attempt_num + random.randint(1, 10)
      logger.warning('FI timeout on attempt %d, retrying in %ds', attempt_num,
                     delay)
      time.sleep(delay)
    except requests.exceptions.RequestException as err:
      logger.error('FI request failed: %s (%s)', _construct_url(api, params),
                   err)
      return None
  return None


def _get_data(resp: Optional[requests.Response], key: str,
              default_value: T) -> T:
  if not resp:
    return default_value
  try:
    data = resp.json()
  except (ValueError, requests.exceptions.InvalidJSONError):
    logger.error('Unable to parse FI response from %s', resp.url)
    return default_value
  content = data.get(key)
  if content or key in data.keys():
    return content
  return default_value


def query_introspector_all_functions(project: str) -> list:
  """Returns every function FI knows about for |project|.

  Each entry includes a ``code_coverage`` field (percentage) which is the
  coverage value LogicFuzz consumes for L5 coverage-aware filtering.
  """
  resp = _query_introspector(INTROSPECTOR_ALL_FUNCTIONS, {'project': project})
  return _get_data(resp, 'functions', [])
