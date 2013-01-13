# -*- coding:utf-8 -*-
import sys
sys.path.append('./src')
from distutils.core import setup
from byd import __version__

setup(name='byd',
      version=__version__,
      description='buy your domain name',
      long_description=open("README.md").read(),
      author='solos',
      author_email='lxl1217@gmail.com',
      packages=['byd'],
      package_dir={'byd':'src/byd'},
      package_data={'byd':['stuff']},
      license="MIT",
      platforms=["any"],
      url='https://github.com/solos/byd'
     )
