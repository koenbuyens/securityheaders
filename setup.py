from setuptools import setup, find_packages

setup(name='advancedsecurityheaders',
      version='0.3',
      description='Python script to check for incorrectly configured security headers.',
      url='http://github.com/koenbuyens/securityheaders',
      author='Koen Buyens',
      author_email='koen@buyens.org',
      license='MIT',
      packages=find_packages(),
      zip_safe=False,
      entry_points = {
        'console_scripts': ['advancedsecurityheaders=securityheaders.command_line:main'],
      },
      install_requires=[
          'enum34',
          'ipaddress',
          'tabulate',
          'anytree',
          'argcomplete',
          'six'
      ])
