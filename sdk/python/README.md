# galleton (Python)

Dependency-free synchronous Python 3.10+ client for an authenticated local Galleton daemon.

```python
from galleton import Galleton
sessions = Galleton.from_dir("./state")
response = sessions.request("account", configured_upstream_url)
print(response.status, response.json())
```

Install this directory with pip or add it to PYTHONPATH. The package has no runtime third-party dependencies. It is not published to PyPI. See the root README and SECURITY.md for provider configuration, the managed-request contract, and limitations.
