from setuptools import setup

setup(name='advancedsecurityheaders',
      version='0.3',
      description='Python script to check for incorrectly configured security headers.',
      url='http://github.com/koenbuyens/securityheaders',
      author='Koen Buyens',
      author_email='koen@buyens.org',
      license='MIT',
      packages=['securityheaders'],
      zip_safe=False,
      entry_points = {
        'console_scripts': ['securityheaders=securityheaders.command_line:main'],
      },
      install_requires=[
          'enum34',
          'ipaddress',
          'tabulate',
          'anytree',
          'argcomplete',
          'six'
      ])
