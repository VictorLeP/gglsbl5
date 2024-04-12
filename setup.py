#!/usr/bin/env python

from setuptools import setup
import versioneer

setup(name='gglsbl5',
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    description="Client library for Google Safe Browsing Update API v5",
    classifiers=[
        "Operating System :: POSIX",
        "Environment :: Console",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Topic :: Internet",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords='google safe browsing api client',
    author='Victor Le Pochat',
    author_email='victor.lepochat@kuleuven.be',
    url='https://github.com/VictorLeP/gglsbl5',
    license='Apache2',
    packages=['gglsbl5'],
    install_requires=['google-api-python-client>=2'],
    scripts=['bin/gglsbl5_client.py'],
)
