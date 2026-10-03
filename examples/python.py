import os
from galleton import Galleton

sessions = Galleton.from_dir(
    os.environ.get("GALLETON_DIR", "./state"),
    os.environ.get("GALLETON_URL", "http://127.0.0.1:8766"),
)
response = sessions.request("demo", "http://127.0.0.1:9909/me")
print(response.status, response.json())
