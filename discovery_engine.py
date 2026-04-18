"""
QShield Discovery Engine
Asynchronously queries Certificate Transparency logs (crt.sh)
to discover associated subdomains.
"""
import httpx
import asyncio
import logging
from typing import List

logger = logging.getLogger("qshield.discovery")

async def discover_subdomains(domain: str, timeout: int = 15) -> List[str]:
    """
    Query crt.sh to find subdomains for a given base domain.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    discovered = set()
    discovered.add(domain)  # Always include the base domain
    
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for name in name_value.split('\n'):
                        name = name.strip().lower()
                        if (name == domain or name.endswith(f".{domain}")) and not name.startswith("*"):
                            discovered.add(name)
            else:
                logger.warning(f"[Discovery] crt.sh returned status {response.status_code}")
    except Exception as e:
        logger.error(f"[Discovery] Failed to query crt.sh for {domain}: {e}")
        
    return sorted(list(discovered))

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        domain = sys.argv[1]
        subs = asyncio.run(discover_subdomains(domain))
        print(f"Discovered {len(subs)} subdomains for {domain}:")
        for s in subs:
            print(f" - {s}")
