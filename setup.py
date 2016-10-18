#!/usr/bin/env python

from setuptools import setup

setup(name='zenoss-fork',

version='0.7.0.0',
    description='Module to work with the Zenoss JSON API (Fork)',
    author="Steve Goossens",
    author_email='steve.goossens@gmail.com',
    url='https://github.com/stevegoossens/python-zenoss',
    py_modules=['zenoss',],
    keywords = ['zenoss', 'api', 'json', 'rest'],
    test_suite='tests'
)
