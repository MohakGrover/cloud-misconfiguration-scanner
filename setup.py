from setuptools import setup, find_packages

setup(
    name="cloud_scanner",
    version="1.0.0",
    description="AWS Cloud Security Scanner",
    packages=find_packages(),
    install_requires=[
        "boto3>=1.28.0",
        "click>=8.1.0",
        "pyyaml>=6.0.0",
        "flask>=3.0.0",
        "duckdb>=0.9.0",
        "python-dateutil>=2.8.0",
        "flask-cors>=4.0.0",
        "jinja2>=3.1.0",
        "python-dotenv>=1.0.0"
    ],
    entry_points={
        "console_scripts": [
            "cloud_scanner=cloud_scanner.cli.commands:cli",
        ],
    },
    python_requires=">=3.9",
)
