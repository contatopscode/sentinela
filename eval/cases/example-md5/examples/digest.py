import hashlib


def example_digest(value):
    return hashlib.md5(value).hexdigest()
