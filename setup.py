from setuptools import setup, find_packages

with open('README.md') as readme_file:
    README = readme_file.read()

setup_args = dict(
    name='shieldsentry',
    version='0.0.9',
    description='ShieldSentry is a Python wrapper for a language agnostic specification created to prevent security attacks.',
    long_description_content_type="text/markdown",
    long_description=README + '\n\n',
    license='Apache',
    packages=find_packages(),
    author='Apratim Shukla',
    author_email='apratimshukla6@gmail.com',
    keywords=['Shield', 'ShieldSentry'],
    url='https://github.com/apratimshukla6/ShieldSentry.py',
    download_url='https://pypi.org/project/shieldsentry/',
    include_package_data=True,
    package_data={
        'shieldsentry': ['specifications.json'],
    }
)

if __name__ == '__main__':
    setup(**setup_args)
