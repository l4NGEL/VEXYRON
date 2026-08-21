from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from core.http_client import HttpClient


@dataclass
class Page:
    url: str
    status_code: int
    headers: dict
    html: str
    forms: list = field(default_factory=list)
    links: list = field(default_factory=list)


def crawl(client: HttpClient, base_url: str, max_pages: int = 30, max_depth: int = 3) -> list[Page]:
    """Base URL'den baslayip ayni domain icinde BFS ile sayfa/form/link kesfi yapar."""
    base_netloc = urlparse(base_url).netloc
    visited: set[str] = set()
    queue = deque([(base_url.rstrip("/") or "/", 0)])
    pages: list[Page] = []

    while queue and len(visited) < max_pages:
        url, depth = queue.popleft()
        if url in visited or depth > max_depth:
            continue
        visited.add(url)

        try:
            resp = client.get(url)
        except requests.exceptions.RequestException:
            continue

        content_type = resp.headers.get("Content-Type", "")
        forms = []
        links = []

        if "text/html" in content_type:
            soup = BeautifulSoup(resp.text, "html.parser")

            for form in soup.find_all("form"):
                action = urljoin(url, form.get("action") or url)
                method = (form.get("method") or "get").lower()
                inputs = []
                for inp in form.find_all(["input", "textarea"]):
                    name = inp.get("name")
                    if name:
                        inputs.append({"name": name, "type": inp.get("type", "text")})
                forms.append({"action": action, "method": method, "inputs": inputs})

            for a in soup.find_all("a", href=True):
                link = urljoin(url, a["href"])
                parsed = urlparse(link)
                if parsed.netloc != base_netloc:
                    continue
                clean = link.split("#")[0]
                if clean not in visited:
                    links.append(clean)
                    if depth + 1 <= max_depth:
                        queue.append((clean, depth + 1))

        pages.append(
            Page(
                url=url,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                html=resp.text if "text/html" in content_type else "",
                forms=forms,
                links=links,
            )
        )

    return pages
