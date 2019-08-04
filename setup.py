from setuptools import setup, find_packages
from distutils.extension import Extension
from Cython.Build import cythonize, build_ext

version = '0.1.8'


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
      package_data={
              'secp256k1py': ['*.pyx',]
      },
      include_package_data=True,
      zip_safe=True,
      install_requires=[
          "point",
          "salsa20>=0.3.0"
      ],
      cmdclass={'build_ext': build_ext},
      ext_modules=cythonize([Extension('*', ['secp256k1py/curv.pyx'])]),
      entry_points="""
      # -*- Entry points: -*-
      """,
      )
