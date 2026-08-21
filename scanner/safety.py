import ipaddress
import socket


class UnauthorizedTargetError(Exception):
    pass


def _resolve_host_ip(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    try:
        return ipaddress.ip_address(socket.gethostbyname(host))
    except socket.gaierror:
        return None


def is_private_or_local(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    ip = _resolve_host_ip(host)
    if ip is None:
        return False
    return bool(ip.is_private or ip.is_loopback)


def assert_authorized(target_host: str, authorized_flag: bool) -> None:
    """Varsayilan olarak yalniz localhost/private IP hedeflere izin verir.

    Baska bir hedefi taramak, izniniz olmayan sistemlere karsi yanlislikla
    kullanimin onune gecmek icin bilincli bir onay gerektirir. Mesaj bilerek
    arayuzden bagimsiz tutulur (CLI bayragi / webapp checkbox'i belirtmez) --
    her cagiran taraf (scanner_cli.py / webapp/app.py) kendi arayuzune uygun
    "nasil devam edilir" talimatini kendisi ekler.
    """
    if authorized_flag:
        return
    if not is_private_or_local(target_host):
        raise UnauthorizedTargetError(
            f"'{target_host}' localhost/private IP araligi disinda. "
            "Bu arac yalniz kendi izniniz olan sistemlerde kullanilmak icin tasarlandi."
        )
