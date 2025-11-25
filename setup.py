from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="shellforge",
    version="3.0.0",
    author="Wael-Rd",
    description="The most comprehensive advanced shell generation framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Wael-Rd/shellforge",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.6",
    entry_points={
        "console_scripts": [
            "shellforge=shellforge.main:main",
        ],
    },
    include_package_data=True,
)
