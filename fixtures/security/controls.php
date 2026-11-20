<?php
// ARTIFICIAL STATIC FIXTURE - DO NOT EXECUTE, serve, or install dependencies.
// Functions are never called; no serialized gadget or command payload is supplied.
function vulnerable_deserialization() {
    $supplied = $_POST['fixture_data'];
    $forwarded = $supplied;
    // ruleid: localguard.security.php-request-unserialize
    return unserialize($forwarded);
}

function vulnerable_explicit_objects() {
    $supplied = $_COOKIE['fixture_data'];
    // ruleid: localguard.security.php-request-unserialize
    return unserialize($supplied, ['allowed_classes' => true]);
}

function clean_deserialization() {
    $supplied = $_POST['fixture_data'];
    // ok: localguard.security.php-request-unserialize
    return json_decode($supplied, true);
}

function clean_no_objects() {
    $supplied = $_POST['fixture_data'];
    // ok: localguard.security.php-request-unserialize
    return unserialize($supplied, ['allowed_classes' => false]);
}

function clean_trusted_deserialization($trusted_local_bytes) {
    // ok: localguard.security.php-request-unserialize
    return unserialize($trusted_local_bytes);
}

function vulnerable_command() {
    $supplied = $_GET['fixture_command'];
    $command = 'fixture-tool ' . $supplied;
    // ruleid: localguard.security.php-request-shell
    return shell_exec($command);
}

function clean_command() {
    $unused = $_GET['fixture_argument'];
    // ok: localguard.security.php-request-shell
    return shell_exec('fixture-tool --version');
}
