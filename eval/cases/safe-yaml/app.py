import yaml


def load(text: str):
    return yaml.safe_load(text)
