from setuptools import setup, find_packages

setup(
    name="packetiq",
    version="1.0.0",
    author="PacketIQ SOC Copilot",
    description="AI PCAP Forensics & SOC Copilot",
    long_description=open("README.md", encoding="utf-8").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "scapy>=2.5.0",
        "click>=8.1.0",
        "rich>=13.0.0",
        "python-dotenv>=1.0.0",
        "tabulate>=0.9.0",
        "colorama>=0.4.6",
        "requests>=2.31.0",
        "anthropic>=0.40.0",
        "fastapi>=0.110.0",
        "uvicorn>=0.29.0",
        "python-multipart>=0.0.9",
    ],
    entry_points={
        "console_scripts": [
            "packetiq=packetiq.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
)
