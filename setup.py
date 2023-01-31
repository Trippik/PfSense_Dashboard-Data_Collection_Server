from setuptools import setup, find_packages

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name="PfSense_Dashboard-Data_Collection_Server",
    version="1.0",
    author="Cameron Trippick",
    install_requires=requirements,
    packages=['syslog_server', 'syslog_server.lib'],
    entry_points={
        'console_scripts': [
            'PfSense_Dashboard-Data_Collection_Server = syslog_server.app:main',
        ]
    }
)