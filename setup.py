from setuptools import setup, find_packages

with open('requirements.txt') as f:
    install_requires = f.read().splitlines()

setup(
    name='pygpoabuse',
    version='0.4.1',
    packages=find_packages(),
    install_requires=install_requires,
    package_data={'': ['*']},
    scripts=['pygpoabuse.py'],
)