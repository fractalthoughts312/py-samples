import os
import sys

import requests
import urllib3



KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "https://keycloak.example.com")
REALM_NAME = os.getenv("KEYCLOAK_REALM", "master")
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "user-checker")
CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET")
INPUT_FILE = os.getenv("INPUT_FILE", "list.txt")
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "result.txt")

def get_token() -> str:
    if not CLIENT_SECRET:
        raise RuntimeError(
            "CLIENT_SECRET не задан. Передайте его через переменную окружения "
            "KEYCLOAK_CLIENT_SECRET."
        )

    token_url = f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/token"
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "client_credentials",
    }

    resp = requests.post(token_url, data=data, verify=VERIFY_SSL, timeout=10)
    resp.raise_for_status()
    return resp.json()["access_token"]


def check_users() -> None:
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}

    with open(INPUT_FILE, "r", encoding="utf-8") as f_in, open(
        OUTPUT_FILE, "w", encoding="utf-8"
    ) as f_out:
        for line in f_in:
            username = line.strip()
            if not username:
                continue

            url = (
                f"{KEYCLOAK_URL}/admin/realms/{REALM_NAME}/users"
                f"?username={requests.utils.quote(username)}&exact=true"
            )

            try:
                resp = requests.get(url, headers=headers, verify=VERIFY_SSL, timeout=10)
                resp.raise_for_status()
                users = resp.json()
            except requests.RequestException as e:
                out = f"{username} — ⚠️ ошибка запроса ({e})\n"
                print(out.strip())
                f_out.write(out)
                continue

            if not users:
                out = f"{username} — ❌ НЕ НАЙДЕН\n"
            else:
                u = users[0]
                first = u.get("firstName", "")
                last = u.get("lastName", "")
                email = u.get("email", "")
                enabled = u.get("enabled", True)
                status = "⚠️ ЗАБЛОКИРОВАН" if not enabled else "✅ Активен"
                out = (
                    f"{username} — {status} | Имя: {first}, "
                    f"Фамилия: {last}, Email: {email}\n"
                )

            print(out.strip())
            f_out.write(out)


if __name__ == "__main__":
    try:
        check_users()
    except Exception as exc:
        print(f"Критическая ошибка: {exc}", file=sys.stderr)
        sys.exit(1)
