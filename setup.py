from setuptools import setup, find_packages

setup(
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "sslmask = sslmask.cli:main",
        ],
    },
    install_requires=[
        "cryptography",
        "uvloop",
    ],
)
