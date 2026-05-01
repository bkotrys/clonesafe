"""Clean setup.py — declarative, no shell-out. Should NOT trigger D17."""

from setuptools import setup, find_packages

setup(
    name="clean-pkg",
    version="1.0.0",
    packages=find_packages(),
    install_requires=["requests>=2.31"],
)
