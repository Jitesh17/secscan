from setuptools import setup, find_packages

setup(
    name="secscan",
    version="0.1.0",
    description="Automated web security scanner with HTML/MD/JSON reports",
    packages=find_packages(),
    include_package_data=True,
    package_data={"secscan": ["templates/*.html", "static/*"]},
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
)
