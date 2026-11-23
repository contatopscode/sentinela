import yaml


def load(text: str):
    return yaml.load(text, Loader=yaml.Loader)
