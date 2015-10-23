from os.path import join, dirname
from setuptools import setup

import uaccounts


with open(join(dirname(__file__), 'README.rst')) as readme:
    README = readme.read()

setup(
    name='django-uaccounts',
    version=uaccounts.__version__,
    author='Aristotelis Mikropoulos',
    author_email='amikrop@gmail.com',
    description='Pluggable user accounts and profiles',
    long_description=README,
    license='BSD',
    url='https://github.com/amikrop/django-uaccounts',
    download_url='https://github.com/amikrop/django-uaccounts',
    packages=['uaccounts'],
    include_package_data=True,
    zip_safe=False,
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
    ],
)
