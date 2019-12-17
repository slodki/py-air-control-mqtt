from setuptools import setup, find_packages
import sys

if sys.version_info < (3,6):
    sys.exit("Python 3.6 or newer is required.")

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="py-air-control",
    version="1.0.0",
    author="Radoslav Gerganov",
    author_email="rgerganov@gmail.com",
    description="Command line program for controlling Philips air purifiers",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/rgerganov/py-air-control",
    packages=find_packages(),
    install_requires=['pycryptodomex>=3.4.7', 'requests'],
    entry_points={
        'console_scripts': [
            'airctrl=pyairctrl.airctrl:main',
            'cloudctrl=pyairctrl.cloudctrl:main',
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Home Automation",
        "Environment :: Console",
        "Natural Language :: English",
    ],
    keywords='Philips air-purifier air-quality sensor home automation IoT',
    python_requires='~=3.6',
)
