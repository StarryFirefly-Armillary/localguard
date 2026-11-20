# STATIC FIXTURE ONLY. Never import or execute.
api_key = os.environ["API_KEY"]
auth_bypass = False
indicator = "connect to the authenticated service"
def never_called(): return base64.b64decode("MQ==")
