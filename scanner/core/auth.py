TOKEN_KEYS = ("token", "access_token", "accessToken", "jwt", "authToken", "auth_token", "idToken", "id_token")


def find_token(data, depth: int = 0):
    """JSON login yanitinda yaygin isimlerle (token/access_token/jwt/...) bir bearer
    token arar; iki seviyeye kadar ic ice sozluklere de bakar (ör. {'data': {'token': '...'}})."""
    if not isinstance(data, dict) or depth > 2:
        return None
    for key in TOKEN_KEYS:
        value = data.get(key)
        if isinstance(value, str) and value:
            return value
    for value in data.values():
        if isinstance(value, dict):
            found = find_token(value, depth + 1)
            if found:
                return found
    return None


def build_login_body(username_field: str, username: str, password: str, extra_fields: dict = None) -> dict:
    body = {username_field: username, "password": password}
    if extra_fields:
        body.update(extra_fields)
    return body


def perform_login(
    client,
    login_url: str,
    username: str,
    password: str,
    *,
    as_json: bool = False,
    username_field: str = "username",
    extra_fields: dict = None,
):
    """Login istegini atar (form-encoded veya JSON) ve yaniti doner.

    JSON yanitta bir bearer token bulunursa (ör. JWT tabanli API'ler), sonraki TUM
    isteklerde otomatik gonderilmesi icin client'in Authorization header'ina
    'Bearer <token>' olarak eklenir. Cookie tabanli oturumlar zaten requests.Session
    tarafindan otomatik yonetildiginden, bu iki mekanizma birbirini bozmadan
    bir arada calisir -- hangi API hangisini kullanirsa kullansin ayni cagriyla
    desteklenir."""
    body = build_login_body(username_field, username, password, extra_fields)
    if as_json:
        resp = client.post(login_url, json=body)
    else:
        resp = client.post(login_url, data=body)

    try:
        data = resp.json()
    except ValueError:
        data = {}
    token = find_token(data)
    if token:
        client.session.headers["Authorization"] = f"Bearer {token}"

    return resp
