SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "x-api-key", "cookie", "set-cookie",
}
SENSITIVE_WORDS = ("key", "token", "secret", "password")


def mask_secret(value):
    text = str(value)
    if len(text) <= 8:
        return "****"
    return text[:2] + "****"


def mask_headers(headers):
    out = {}
    for name, value in (headers or {}).items():
        lower = name.lower()
        if lower in SENSITIVE_HEADERS or any(w in lower for w in SENSITIVE_WORDS):
            text = str(value)
            if " " in text:
                scheme, rest = text.split(" ", 1)
                out[name] = scheme + " " + mask_secret(rest)
            else:
                out[name] = mask_secret(text)
        else:
            out[name] = value
    return out
