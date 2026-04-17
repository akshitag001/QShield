"""
QShield VPN Scanner
Detects common VPN endpoints on public assets.
"""
import httpx
import asyncio
import socket
import logging
from typing import List, Union

logger = logging.getLogger("qshield.vpn")

async def check_http_vpn(host: str, ports: List[int], timeout: int = 5) -> dict:
    """Async probe for common web-based VPN interfaces."""
    vpn_info = {
        "detected": False,
        "vpn_type": None,
        "endpoint": None,
        "checked_ports": [],
        "checked_urls": []
    }

    probes = [
        ("/+CSCOE+/logon.html", "Cisco AnyConnect", ["cisco", "anyconnect", "webvpn", "portal"]),
        ("/remote/login", "Fortinet FortiGate", ["forti", "fortigate", "sslvpn", "vpn"]),
        ("/global-protect/login.esp", "Palo Alto GlobalProtect", ["globalprotect", "palo", "panos", "vpn"]),
        ("/dana-na/auth/url_default/welcome.cgi", "Pulse Secure", ["pulse", "dana", "juniper", "vpn"]),
        ("/dana-na/", "Pulse Secure", ["pulse", "dana", "juniper", "vpn"]),
        ("/sslvpn/Logon.jsp", "SonicWall", ["sonicwall", "sslvpn", "vpn"]),
        ("/sslvpn/login", "SonicWall", ["sonicwall", "sslvpn", "vpn"]),
        ("/my.policy", "F5 BIG-IP APM", ["f5", "big-ip", "apm", "my.policy", "vpn"]),
        ("/myvpn/", "Check Point", ["checkpoint", "check point", "vpn", "remote access"]),
        ("/vpn/index.html", "Generic VPN", ["vpn", "remote access", "secure access"]) 
    ]

    transport = httpx.AsyncHTTPTransport(verify=False, retries=0)
    async with httpx.AsyncClient(transport=transport, timeout=timeout, follow_redirects=True) as client:
        async def probe_url(url: str, name: str, keywords: list[str]):
            try:
                resp = await client.get(url)
                body = (resp.text or "").lower()
                headers = " ".join([str(v).lower() for v in resp.headers.values()])
                status_ok = resp.status_code in (200, 301, 302, 401, 403)
                if status_ok and any(k in body or k in headers for k in keywords):
                    return name, url
            except Exception:
                pass
            return None

        tasks = []
        for port in ports:
            schemes = ["https", "http"]
            if port in {80, 8080, 8000}:
                schemes = ["http"]
            elif port in {443, 8443, 10443, 1443, 9443, 9444, 4443}:
                schemes = ["https"]

            for scheme in schemes:
                base_url = f"{scheme}://{host}:{port}"
                for path, name, keywords in probes:
                    url = f"{base_url}{path}"
                    vpn_info["checked_urls"].append(url)
                    tasks.append(probe_url(url, name, keywords))

        results = await asyncio.gather(*tasks) if tasks else []
        for res in results:
            if res:
                vpn_info["detected"] = True
                vpn_info["vpn_type"] = res[0]
                vpn_info["endpoint"] = res[1]
                logger.debug(f"[VPN Scanner] Detected {res[0]} at {res[1]}")
                break

    vpn_info["checked_ports"] = list(dict.fromkeys(ports))
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

async def scan_vpn(host: str, ports: Union[int, List[int]], timeout: int = 5) -> dict:
    port_list = [ports] if isinstance(ports, int) else list(ports or [])
    port_list = [p for p in port_list if isinstance(p, int) and 1 <= p <= 65535]
    port_list = list(dict.fromkeys(port_list))

    http_future = check_http_vpn(host, port_list, timeout)
    udp_future = check_openvpn(host, timeout)

    http_res, udp_res = await asyncio.gather(http_future, udp_future)
    if http_res.get("detected"):
        return http_res
    if udp_res.get("detected"):
        udp_res["checked_ports"] = port_list
        return udp_res

    return {
        "detected": False,
        "vpn_type": None,
        "endpoint": None,
        "checked_ports": port_list
    }
