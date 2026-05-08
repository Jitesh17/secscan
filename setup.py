from pathlib import Path

from setuptools import find_packages, setup

ROOT = Path(__file__).parent
LONG_DESCRIPTION = (ROOT / "README.md").read_text(encoding="utf-8")

setup(
    name="secscan-tool",
    version="0.1.0",
    description=(
        "Automated web security scanner with HTML/Markdown/JSON reports "
        "and AI-tailored remediation"
    ),
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    author="Jitesh Gosar",
    author_email="gosar95@gmail.com",
    license="MIT",
    url="https://github.com/Jitesh17/secscan",
    project_urls={
        "Source": "https://github.com/Jitesh17/secscan",
        "Issues": "https://github.com/Jitesh17/secscan/issues",
        "Changelog": "https://github.com/Jitesh17/secscan/releases",
    },
    keywords=[
        "security",
        "scanner",
        "vulnerability",
        "pentesting",
        "appsec",
        "nuclei",
        "zap",
        "owasp",
        "tls",
        "headers",
        "remediation",
        "devsecops",
    ],
    packages=find_packages(exclude=["tests", "tests.*"]),
    include_package_data=True,
    package_data={"secscan": ["templates/*.html"]},
    install_requires=[
        "click>=8.1.0",
        "rich>=13.7.0",
        "requests>=2.31.0",
        "jinja2>=3.1.0",
        "pyyaml>=6.0",
        "fastapi>=0.110.0",
        "uvicorn[standard]>=0.27.0",
        "sslyze>=5.2.0",
        "python-multipart>=0.0.9",
    ],
    entry_points={
        "console_scripts": [
            "secscan=secscan.cli:main",
        ],
    },
    python_requires=">=3.10",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS :: MacOS X",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: System :: Networking :: Monitoring",
    ],
)
