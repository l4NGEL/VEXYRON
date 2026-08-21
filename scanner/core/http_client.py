import time

import requests


class HttpClient:
    """requests.Session etrafinda ince bir sarmalayici: sabit timeout, istege bagli
    istekler-arasi gecikme (rate limiting) ve toplam istek sayaci saglar."""

    def __init__(self, timeout: float = 5.0, delay: float = 0.0, user_agent: str = "pentest-lab-scanner/1.0"):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        self.timeout = timeout
        self.delay = delay
        self.request_count = 0

    def _sleep(self):
        if self.delay:
            time.sleep(self.delay)

    def get(self, url: str, **kwargs) -> requests.Response:
        self.request_count += 1
        self._sleep()
        kwargs.setdefault("timeout", self.timeout)
        return self.session.get(url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        self.request_count += 1
        self._sleep()
        kwargs.setdefault("timeout", self.timeout)
        return self.session.post(url, **kwargs)

    def cookies_dict(self) -> dict:
        return self.session.cookies.get_dict()
