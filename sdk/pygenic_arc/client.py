import requests

class ArcGuard:
    def __init__(self, base_url: str, api_key: str, timeout: int = 10):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout

    def authorize(self, agent: str, tool: str, parameters=None, authorization=False, state=None):
        r = requests.post(self.base_url + '/v1/agent/action', headers={'X-API-Key': self.api_key}, json={
            'agent_id': agent, 'tool': tool, 'parameters': parameters or {},
            'authorization': authorization, 'state': state or {}
        }, timeout=self.timeout)
        r.raise_for_status()
        return r.json()
