from os import path
from setuptools import find_packages, setup


here = path.abspath(path.dirname(__file__))

# Get the long description from the relevant file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

with open(path.join(here, "requirements.txt")) as f:
    deps = [l.strip() for l in f.readlines() if l.strip() != "" and not l.strip().startswith("#")]

setup(
    name='cherimoya_helpers',
    version='1.0.12',
    description='Useful python helpers for lambda',
    url='https://github.com/joacimfloren/cherimoya_helpers.git',
    author='Joacim Florén',
    author_email='joacim.floren@gmail.com',
    license='MIT',
    packages=find_packages(),
    # zip_safe=False
    long_description_content_type="text/markdown",
    long_description=long_description,
    install_requires=deps,
    include_package_data=True,
)