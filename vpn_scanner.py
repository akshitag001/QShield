"""
QShield VPN Scanner
Detects common VPN endpoints on public assets.
"""
import httpx
import asyncio
import socket
import logging

logger = logging.getLogger("qshield.vpn")

async def check_http_vpn(host: str, port: int, timeout: int = 5) -> dict:
    """Async probe for common web-based VPN interfaces."""
    vpn_info = {
        "detected": False,
        "vpn_type": None,
        "endpoint": None
    }
    
    base_url = f"https://{host}:{port}"
    probes = {
        "/+CSCOE+/logon.html": "Cisco AnyConnect",
        "/remote/login": "Fortinet FortiGate",
        "/global-protect/login.esp": "Palo Alto GlobalProtect"
    }
    
    transport = httpx.AsyncHTTPTransport(verify=False, retries=0)
    async with httpx.AsyncClient(transport=transport, timeout=timeout, follow_redirects=True) as client:
        async def probe_path(path: str, name: str):
            try:
                url = f"{base_url}{path}"
                resp = await client.get(url)
                body = resp.text.lower()
                if resp.status_code == 200 and ("vpn" in body or "login" in body or "cisco" in body or "forti" in body or "globalprotect" in body):
                    return name, url
            except Exception:
                pass
            return None
            
        tasks = [probe_path(path, name) for path, name in probes.items()]
        results = await asyncio.gather(*tasks)
        
        for res in results:
            if res:
                vpn_info["detected"] = True
                vpn_info["vpn_type"] = res[0]
                vpn_info["endpoint"] = res[1]
                logger.debug(f"[VPN Scanner] Detected {res[0]} at {res[1]}")
                break
                
    return vpn_info

async def check_openvpn(host: str, timeout: int = 3) -> dict:
    """Probe for OpenVPN UDP 1194 banner."""
    vpn_info = {"detected": False, "vpn_type": None, "endpoint": None}
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    
    try:
        packet = b"\x38" + b"\x00" * 13 
        await loop.sock_sendto(sock, packet, (host, 1194))
        try:
            data, addr = await asyncio.wait_for(loop.sock_recvfrom(sock, 1024), timeout=timeout)
            if data and len(data) >= 1 and data[0] == 0x40:
                vpn_info["detected"] = True
                vpn_info["vpn_type"] = "OpenVPN"
                vpn_info["endpoint"] = f"udp://{host}:1194"
        except asyncio.TimeoutError:
            pass
    except Exception:
        pass
    finally:
        sock.close()
        
    return vpn_info

async def scan_vpn(host: str, port: int, timeout: int = 5) -> dict:
    http_future = check_http_vpn(host, port, timeout)
    udp_future = check_openvpn(host, timeout)
    
    http_res, udp_res = await asyncio.gather(http_future, udp_future)
    if http_res["detected"]: return http_res
    if udp_res["detected"]: return udp_res
    
    return {"detected": False, "vpn_type": None, "endpoint": None}
