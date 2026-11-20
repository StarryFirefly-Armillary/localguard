# ARTIFICIAL STATIC FIXTURE - DO NOT EXECUTE, import, or install dependencies.
# Names and data are inert examples; findings are rule matches, not exploit proof.
import json
import os
import pickle
import sqlite3
import subprocess

from flask import request
import requests as http_client


def vulnerable_shell():
    supplied = request.args.get("fixture_command")
    command = "fixture-tool " + supplied
    # ruleid: localguard.security.python-request-shell
    subprocess.run(command, shell=True)


def clean_shell():
    supplied = request.args.get("fixture_argument")
    # ok: localguard.security.python-request-shell
    subprocess.run(["fixture-tool", supplied], shell=False)
    # ok: localguard.security.python-request-shell
    os.system("fixture-tool --version")
    supplied = "fixture-tool --version"
    # ok: localguard.security.python-request-shell
    subprocess.run(supplied, shell=True)


def vulnerable_pickle():
    supplied = request.get_data()
    forwarded = supplied
    # ruleid: localguard.security.python-request-pickle
    return pickle.loads(forwarded)


def clean_pickle():
    supplied = request.get_data()
    # ok: localguard.security.python-request-pickle
    return json.loads(supplied)


def clean_trusted_pickle(trusted_local_bytes):
    # ok: localguard.security.python-request-pickle
    return pickle.loads(trusted_local_bytes)


def vulnerable_tls(endpoint):
    # ruleid: localguard.security.python-requests-no-cert-validation
    return http_client.get(endpoint, verify=False)


def clean_tls(endpoint):
    # ok: localguard.security.python-requests-no-cert-validation
    return http_client.get(endpoint, verify=True)


def vulnerable_sql():
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    supplied = request.args.get("fixture_name")
    query = "SELECT label FROM fixture_items WHERE label = '" + supplied + "'"
    # ruleid: localguard.security.python-request-sqlite-query
    return cursor.execute(query)


def vulnerable_connection_sql():
    conn = sqlite3.connect(":memory:")
    supplied = request.form.get("fixture_name")
    query = "SELECT label FROM fixture_items WHERE label = '" + supplied + "'"
    # ruleid: localguard.security.python-request-sqlite-query
    return conn.execute(query)


def clean_sql():
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    supplied = request.args.get("fixture_name")
    # ok: localguard.security.python-request-sqlite-query
    return cursor.execute("SELECT label FROM fixture_items WHERE label = ?", (supplied,))


def clean_non_database(renderer):
    supplied = request.args.get("fixture_name")
    # ok: localguard.security.python-request-sqlite-query
    return renderer.execute(supplied)


def clean_literal_controls():
    # ok: localguard.security.python-requests-no-cert-validation
    documentation = "requests.get(endpoint, verify=False)"
    # ok: localguard.security.python-request-shell
    arithmetic = eval("1 + 2")
    return documentation, arithmetic
