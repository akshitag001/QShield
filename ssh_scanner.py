"""
QShield SSH Scanner
NIST SP 1800-38B Compliance Check
"""
import paramiko
import asyncio
import logging
from typing import List, Optional, Union

logger = logging.getLogger("qshield.ssh")

def _probe_ssh_sync(host: str, port: int = 22, timeout: int = 5) -> dict:
    ssh_info = {
        "detected": False,
        "banner": None,
        "kex_algorithms": [],
        "ciphers": []
    }
    
    try:
        t = paramiko.Transport((host, port))
        t.start_client(timeout=timeout)
        
        ssh_info["detected"] = True
        ssh_info["banner"] = getattr(t, 'remote_version', 'Unknown SSH Server')
        
        try:
            sec = t.get_security_options()
            ssh_info["kex_algorithms"] = list(sec.kex) if sec.kex else []
            ssh_info["ciphers"] = list(sec.ciphers) if sec.ciphers else []
        except Exception as e:
            pass
            
        t.close()
    except Exception as e:
        pass
        
    return ssh_info

def _normalize_ports(ports: Union[int, List[int], None]) -> List[int]:
    if ports is None:
        return [22]
    if isinstance(ports, int):
        ports = [ports]
    normalized = []
    for port in ports:
        try:
            value = int(port)
        except (TypeError, ValueError):
            continue
        if 1 <= value <= 65535 and value not in normalized:
            normalized.append(value)
    return normalized or [22]


async def scan_ssh(host: str, ports: Union[int, List[int]] = 22, timeout: int = 5) -> dict:
    """Async wrapper for SSH probe"""
    port_list = _normalize_ports(ports)
    checked = []

    for port in port_list:
        checked.append(port)
        ssh_info = await asyncio.to_thread(_probe_ssh_sync, host, port, timeout)
        if ssh_info.get("detected"):
            ssh_info["port"] = port
            ssh_info["checked_ports"] = checked
            return ssh_info

    return {
        "detected": False,
        "banner": None,
        "kex_algorithms": [],
        "ciphers": [],
        "checked_ports": checked
    }
