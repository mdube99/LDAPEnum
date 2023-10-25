from setuptools import setup, find_packages

long_description = open('README.md').read()

setup(name='fvm-ldap-enum',
    version='0.5.2',
    description='Frontline LDAP Enumeration tool using pywerview',
    long_description=long_description,
    long_description_content_type='text/markdown',
    dependency_links = ['https://github.com/the-useless-one/pywerview/tarball/master#egg=pywerview-0.5.2'],
    classifiers=[
        'Environment :: Console',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Programming Language :: Python :: 3.6',
        'Topic :: Security',
    ],
    keywords='python powersploit pentesting recon active directory windows',
    url='https://github.com/the-useless-one/pywerview',
    author='Yannick Méheut',
    author_email='yannick@meheut.org',
    license='GNU GPLv3',
    packages=find_packages(include=[
        "fvm-ldap-enum", "fvm-ldap-enum.*"
    ]),
    install_requires=[
        'pywerview',
        'ldap',
    ],
    entry_points = {
        'console_scripts': ['fvm_ldap_enum=fvm-ldap-enum.enum:main'],
    },
    zip_safe=False)
