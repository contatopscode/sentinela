import subprocess


def run(command):
    return subprocess.Popen(command, shell=True)
