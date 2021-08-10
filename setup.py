import setuptools
import platform

platform_system = platform.system()

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="detect_wrapper",
    version="0.7-Beta",
    author="Matthew Brady",
    author_email="w3matt@gmail.com",
    description="Python wrapper for Synopsys Detect with XML and HTML outputs.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/matthewb66/detect_wrapper",
    packages=setuptools.find_packages(),
    install_requires=['blackduck>=1.0.4',
                      'lxml',
                      'dominate',
                      'requests',
                      'tabulate',
                      ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.8',
    entry_points={
        'console_scripts': ['detect_wrapper=detect_wrapper.main:main'],
    },
)
