#! /usr/bin/env python
"""Screen for license non-compliance focus - only GPL for now."""
# pylint: disable=expression-not-assigned,invalid-name,line-too-long,too-many-locals
import subprocess
import copy
import datetime as dti
import hashlib
import json
import lzma
import os
import pathlib
import sys

import git

BUFFER_BYTES = 2 << 15
NON_EXISTING_HASH = 'abadcafe' * 8
HASHING_ID_PREFIX = 'sha256:'

ENCODING = "utf-8"
ERRORS = "ignore"
TIMEPOINT_FORMAT = "%Y%m%dT%H%M"
REPORT_DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'
FROM_EPOC_MILLIS_FORMAT = REPORT_DATETIME_FORMAT

DUMMY_PRODUCT = "NNProduct"
DUMMY_PROJECT = "NNProject"
DUMMY_REPO = "NNRepo"
DUMMY_BRANCH = "NNBranch"
DUMMY_COMMIT = "cafefadecafefadecafefadecafefadecafefade"

LICENSE_TOPIC = 'GPL'
LICENSE_TOKEN = LICENSE_TOPIC
PARENT_CODE = '/'
REL_TARGET_PATH = ''

REPO_PRODUCT_MAPPING = os.getenv("REPO_PRODUCT_MAPPING", "")
DEBUG = os.getenv("LICENSE_SCREENING_DEBUG", "")


def load_json(file_handle, file_path):
    """Load pull request data from json file path."""
    try:
        return json.load(file_handle)
    except UnicodeDecodeError as err:
        print("# UnicodeDecodeError in", file_path, str(err))
        sys.stdout.flush()
        raise


def load(file_path):
    """Accept json and xz (lzma)"""
    if pathlib.Path(file_path).suffix == ".xz":
        with lzma.open(file_path) as json_source:
            return load_json(json_source, file_path)
    else:
        with open(file_path, 'rt', encoding=ENCODING) as json_source:
            return load_json(json_source, file_path)


def load_mapping():
    """SOC"""
    product_from_repo, have_mapping = {}, False
    try:
        product_from_repo = json.loads(REPO_PRODUCT_MAPPING)
        have_mapping = True
    except json.decoder.JSONDecodeError:
        pass

    if not have_mapping:
        path = pathlib.Path(REPO_PRODUCT_MAPPING)
        if path.is_file():
            with open(path, "rt", encoding=ENCODING) as handle:
                product_from_repo = json.load(handle)
            have_mapping = True

    return product_from_repo


def version_context():
    """Retrieve version context (in good faith)."""
    repo = git.Repo(search_parent_directories=True)
    # url = some/path/to/anything/project/repository
    project_name, repo_name = repo.remotes.origin.url.split('.git')[0].split('/')[-2:]
    branch_name = repo.active_branch.name
    revision = repo.head.object.hexsha
    return branch_name, project_name, repo_name, revision


def hash_size(path_string, get_size=os.path.getsize):
    """Yield hash and byte size of path."""
    path = pathlib.Path(path_string)
    if not path.is_file():
        return NON_EXISTING_HASH, 0
    with open(path, "rb") as in_file:
        sha256_hash = hashlib.sha256()
        for byte_block in iter(lambda in_f=in_file: in_f.read(BUFFER_BYTES), b""):
            sha256_hash.update(byte_block)

    return sha256_hash.hexdigest(), get_size(path)


def parse(thing):
    """Connect the dots ... later (TODO)."""
    return NotImplemented


def main(argv=None):
    """Drive the detection, assessment, and aggregation."""
    argv = sys.argv[1:] if argv is None else argv
    DEBUG and print(argv)

    product_from_repo = load_mapping()
    if not product_from_repo:
        print("ERROR in gathering repo to product mapping (did you set REPO_PRODUCT_MAPPING?) ... giving up")
        return 1

    start_of_analysis = dti.datetime.now()
    branch_name, project_name, repo_name, revision = version_context()
    command = ["grep", "-r", LICENSE_TOKEN]
    report = {
        "_meta": {
            "audit": "assessment",
            "domain": "license",
            "topic": LICENSE_TOPIC,
            "pwd": PARENT_CODE,
            "command": " ".join(command),
            "product": product_from_repo.get(repo_name, "NNProduct"),
            "project": project_name.lower(),
            "repository": repo_name.lower(),
            "branch": branch_name,
            "commit": revision},
        "assessment": [],
        "findings": {
            "compliant_count": 0,
            "defect_count": 0,
            "inconclusive_count": 0,
            "total_count": 0,
            "total_bytes": 0
        },
        "data_version": start_of_analysis.strftime(REPORT_DATETIME_FORMAT)
    }
    finding_template = {"path": "", "method_hash": "", "size_bytes": 0, "finding": "", "compliant": False}

    compliant_count, defect_count, total_count, total_bytes = 0, 0, 0, 0
    print(f'# processing LICENSE_TOKEN::{LICENSE_TOKEN} ...')
    for target_root in argv:
        local_path = pathlib.Path(target_root)
        if not local_path.is_dir():
            print(f'#   ignoring tree below non-existing({target_root}) ...')
            continue

        print(f'#   assessing tree below({target_root}) ...')
        local_command = copy.deepcopy(command) + [target_root]

        print(f'#    command({local_command})')
        try:
            line_report = subprocess.check_output(local_command, stderr=subprocess.STDOUT).decode()
            success = True
        except subprocess.CalledProcessError as e:
            line_report = e.output.decode()
            success = False
        DEBUG and print(line_report)
        if not success:
            print("ERROR in gathering subprocess ... giving up")
            return 1
        for line in line_report.split("\n"):
            if ":" not in line:
                continue
            total_count += 1
            location, hit = line.strip().split(":", 1)
            location_hash, location_size = hash_size(location)
            total_bytes += location_size
            if location_hash == NON_EXISTING_HASH:
                print(f'WARNING: Bad location({location})')
            if not location_size:
                print(f'WARNING: Empty location({location})')
            hit = hit.strip()
            compliant = "lesser" in hit.lower() or "LGPL" in hit
            if compliant:
                compliant_count += 1
            else:
                defect_count += 1
            finding = copy.deepcopy(finding_template)
            finding["path"] = location
            finding["method_hash"] = f'{HASHING_ID_PREFIX}{location_hash}'
            finding["size_bytes"] = location_size
            finding["finding"] = hit
            finding["compliant"] = compliant
            report["assessment"].append(finding)

    inconclusive_count = total_count - (compliant_count + defect_count)
    report["findings"] = {
        "compliant_count": compliant_count,
        "defect_count": defect_count,
        "inconclusive_count": inconclusive_count,
        "total_count": total_count,
        "total_bytes": total_bytes,
    }

    print()
    with open(f"license_assessment-{LICENSE_TOPIC}_via-{LICENSE_TOKEN}_{start_of_analysis.strftime(TIMEPOINT_FORMAT)}_v0.json", "wt", encoding=ENCODING) as handle:
        json.dump(report, handle, indent=2)

    return 0
