from setuptools import setup, find_packages
import os

# Read README for long description
readme_path = os.path.join(os.path.dirname(__file__), "README.md")
if os.path.exists(readme_path):
    with open(readme_path, "r", encoding="utf-8") as fh:
        long_description = fh.read()
else:
    long_description = "ShellForge - The Insane Shell Generator"

setup(
    name="shellforge",
    version="3.3.0",
    author="Wael-Rd",
    author_email="",
    description="The most comprehensive advanced shell generation framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Wael-Rd/shellforge",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Environment :: Console",
    ],
    python_requires=">=3.6",
    entry_points={
        "console_scripts": [
            "shellforge=shellforge.main:main",
        ],
    },
    include_package_data=True,
    keywords=["security", "pentesting", "shell", "reverse-shell", "red-team"],
)
