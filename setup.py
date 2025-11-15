from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="vuln-scanner",
    version="1.0.0",
    author="Tu Nombre",
    author_email="tu-email@example.com",
    description="Herramienta profesional de escaneo de vulnerabilidades",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tu-usuario/vuln-scanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.8",
    install_requires=[
        "python-nmap>=0.7.1",
        "colorama>=0.4.6",
        "pyyaml>=6.0.1",
        "requests>=2.31.0",
        "tabulate>=0.9.0",
        "netifaces>=0.11.0",
        "scapy>=2.5.0",
    ],
    entry_points={
        "console_scripts": [
            "vuln-scan=vuln_scan:main",
        ],
    },
)