import os
from galleton import Galleton

sessions = Galleton.from_dir(os.environ.get("GALLETON_DIR", "./state"))
response = sessions.request("demo", "http://127.0.0.1:9909/me")
print(response.status, response.json())
