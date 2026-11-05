"""The Lambda package Terraform builds holds every module the functions import."""

import os
import re

ROOT = os.path.join(os.path.dirname(__file__), "..")


def test_lambda_tf_packages_every_module():
    tf = open(os.path.join(ROOT, "lambda.tf")).read()
    packaged = set(re.findall(r'"(\w+\.py)"', re.search(r"for_each = toset\(\[(.*?)\]\)", tf).group(1)))
    on_disk = {f for f in os.listdir(os.path.join(ROOT, "lambda", "perimeter")) if f.endswith(".py")}
    assert packaged == on_disk


def test_every_handler_named_in_terraform_exists():
    import app

    tf = open(os.path.join(ROOT, "lambda.tf")).read()
    names = re.findall(r"^    (\w+) = \{\n      description", tf, re.M)
    assert names == ["planner", "scanner", "judge", "tripwire"]
    assert all(callable(getattr(app, n)) for n in names)
