def requires_security(cookie):
    name = cookie.name()
    if not name:
        return False
    name = name.lower()
    if name.startswith('__Secure'):
        return True
    if name.startswith('__Host'):
        return True
    if 'session' in name:
        return True
    if 'csrf' in name:
        return True
    return False
