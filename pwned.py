import subprocess
import json
import hashlib
import requests
from typing import Dict, Any
import sys


def get_hash(password: str) -> str:
    m = hashlib.sha1()
    m.update(password)
    password_hash = m.hexdigest().upper()
    return password_hash


def get_pwned(password_hash: str) -> Dict[str, int]:
    key = password_hash[0:5]
    res = requests.get(f"https://api.pwnedpasswords.com/range/{key}")
    assert res.status_code == 200
    lines = res.text.splitlines()
    pairs = [line.split(":") for line in lines]
    results = {f"{key}{ending}": int(count) for ending, count in pairs}
    return results


def get_credentials(*args) -> Dict[str, Any]:
    print('DEBUG')
    print(args)
    if args is not None:
        result = subprocess.run(["bw", "list", "items", "--session", args], capture_output=True)
    else:
        result = subprocess.run(["bw", "list", "items"], capture_output=True)
    items = json.loads(result.stdout)
    return [item for item in items if "login" in item]


def main():
    count_pwned = 0
    BW_SESSION = None
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        assert arg in ['--session'], \
                'Use --session to use BW_SESSION secret key'
        try:
            BW_SESSION = sys.argv[2]
        except:
            print('Secret key is empty, using system exported BW_SESSION')
    credentials = get_credentials(BW_SESSION)
    for item in credentials:
        if not item["login"]["password"]:
            continue
        password = item["login"]["password"].encode("utf-8")
        password_hash = get_hash(password)
        results = get_pwned(password_hash)
        pwned = password_hash in results
        if not pwned:
            continue
        count_pwned += 1
        print(f"{item['login']['uris'][0]['uri']}:{item['login']['username']}:{item['login']['password']} has been pwned!")

    print(f"{count_pwned} of {len(credentials)} logins have been pwned.")


if __name__ == "__main__":
    sys.exit(main())
