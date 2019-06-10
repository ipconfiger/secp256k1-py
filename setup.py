from setuptools import setup, find_packages
import sys, os

version = '0.0.1'

setup(name='secp256k1py',
      version=version,
      description="Python version secp256k1 keypair generator signature and verify, ecdh secret sharing, for human mind",
      long_description="""\
Python version secp256k1 keypair generator signature and verify, ecdh secret sharing, for human mind""",
      classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords='ecc,ecdh,secp256k1,signature,verification',
      author='Alexander.Li',
      author_email='superpowerlee@gmail.com',
      url='https://github.com/ipconfiger/secp256k1-py',
      license='MIT',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=True,
      install_requires=[
          "point"
      ],
      entry_points="""
      # -*- Entry points: -*-
      """,
      )
