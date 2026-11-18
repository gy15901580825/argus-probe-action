import json
import time
from pathlib import Path
from argus.demo import bypass_proxy_for_localhost
from argus.demo.servers import PROBE_IDS, start_mcp_demo
bypass_proxy_for_localhost()
with start_mcp_demo() as spec:
    Path('.scratch/target.json').write_text(json.dumps(spec))
    Path('.scratch/probes.txt').write_text(','.join(PROBE_IDS))
    Path('.scratch/ready').touch()
    while not Path('.scratch/stop').exists():
        time.sleep(0.2)
