import ipaddress
import socket
import nmap
import traceback
import hashlib
import time
from datetime import datetime
from netbios_scan import get_netbios_info
from mdns_scan import scan_mdns
from upnp_scan import discover_upnp
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from packet_capture import get_connection_type
from oui_lookup import lookup_vendor
from snmp_scan import scan_snmp

VENDOR_MAP = {
    "hp": "HP",
    "dell": "Dell",
    "lenovo": "Lenovo",
    "canon": "Canon",
    "epson": "Epson",
    "apple": "Apple",
    "samsung": "Samsung",
    "xiaomi": "Xiaomi",
    "tp-link": "TP-Link",
    "tplink": "TP-Link",
    "hikvision": "Hikvision",
    "realtek": "Realtek",
    "intel": "Intel",
    "raspberry": "Raspberry Pi",
    "ubiquiti": "Ubiquiti",
    "mikrotik": "MikroTik",
    "asus": "ASUS",
    "acer": "Acer",
    "msi": "MSI",
    "sony": "Sony",
    "lg": "LG",
    "oppo": "OPPO",
    "vivo": "Vivo",
    "oneplus": "OnePlus",
    "huawei": "Huawei",
    "honor": "Honor",
    "brother": "Brother",
    "zebra": "Zebra",
    "cisco": "Cisco",
    "juniper": "Juniper",
    "fortinet": "Fortinet",
    "netgear": "Netgear",
    "d-link": "D-Link"
}

DEVICE_TYPE_MAP = {
    "windows": "Windows PC",
    "linux": "Linux System",
    "android": "Android Device",
    "ios": "Apple Device",
    "printer": "Printer",
    "router": "Router",
    "camera": "IP Camera",
    "switch": "Network Switch",
    "firewall": "Firewall",
    "nas": "NAS",
    "tv": "Smart TV"
}

def get_local_subnet():
    """
    Returns the local subnet in CIDR format.
    Example: 192.168.0.0/24
    """

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()

    network = ipaddress.IPv4Network(
        local_ip + "/24",
        strict=False
    )

    return str(network)


def reverse_dns_lookup(ip):

    try:

        hostname, alias, addresses = socket.gethostbyaddr(ip)

        return {
            "hostname": hostname,
            "aliases": alias,
            "addresses": addresses,
            "success": True
        }

    except Exception:

        return {
            "hostname": "",
            "aliases": [],
            "addresses": [],
            "success": False
        }

def get_os(data):

    try:
        osmatch = data.get("osmatch", [])
        if osmatch:
            return osmatch[0].get("name", "")

    except Exception:
        pass

    try:

        for proto in data.all_protocols():
            for port in data[proto]:
                product = data[proto][port].get("product", "")
                version = data[proto][port].get("version", "")
                if product:
                    if version:
                        return f"{product} {version}"

                    return product

    except Exception:
        pass

    return ""


def get_open_ports(data):

    ports = []
    try:

        for proto in data.all_protocols():
            for port in data[proto]:
                if data[proto][port]["state"] == "open":
                    ports.append(str(port))

    except Exception:
        pass

    return ", ".join(
        sorted(
            ports,
            key=int
        )
    )

def get_port_details(data):

    ports = []
    try:

        for proto in data.all_protocols():
            for port in data[proto]:
                if data[proto][port]["state"] == "open":
                    ports.append({
                        "protocol": proto,
                        "port": port,
                        "service": data[proto][port].get("name", ""),
                        "product": data[proto][port].get("product", ""),
                        "version": data[proto][port].get("version", "")
                    })

    except Exception:
        pass

    return ports

def get_services(data):

    services = []
    try:

        for proto in data.all_protocols():
            for port in data[proto]:
                service = data[proto][port].get("name", "")
                if service:
                    services.append(service)

    except Exception:
        pass

    return ", ".join(sorted(set(services)))


def scan_network():

    # scan_time = datetime.now().strftime("%d-%b-%Y %I:%M:%S %p")
    scan_time = time.time()

    try:
        nm = nmap.PortScanner(
            nmap_search_path=(
                r"C:\Program Files (x86)\Nmap\nmap.exe",
                r"C:\Program Files\Nmap\nmap.exe"
            )
        )

    except Exception as e:
        raise Exception(f"Nmap initialization failed : {e}")

    subnet = get_local_subnet()

    with ThreadPoolExecutor(max_workers=3) as executor:

        future_mdns = executor.submit(scan_mdns)
        future_upnp = executor.submit(discover_upnp)

        nm.scan(
            hosts=subnet,
            arguments="-O -sV -Pn --osscan-guess --host-timeout 20s"
        )

        mdns_devices = future_mdns.result()
        upnp_devices = future_upnp.result()


    devices = []

    hosts = sorted(
        nm.all_hosts(),
        key=lambda ip: tuple(map(int, ip.split(".")))
    )

    snmp_devices = {}

    with ThreadPoolExecutor(max_workers=20) as executor:

        futures = {
            executor.submit(scan_snmp, host): host
            for host in hosts
        }

        for future in as_completed(futures):

            host = futures[future]
            try:
                snmp_devices[host] = future.result()
            except Exception:
                snmp_devices[host] = {}

    netbios_devices = {}

    with ThreadPoolExecutor(max_workers=20) as executor:

        futures = {
            executor.submit(get_netbios_info, host): host
            for host in hosts
        }

        for future in as_completed(futures):

            host = futures[future]

            try:
                netbios_devices[host] = future.result()

            except Exception:
                netbios_devices[host] = {}

    reverse_dns_cache = {}

    connection_type = get_connection_type()
    
    for host in hosts:

        try:

            data = nm[host]
            netbios = netbios_devices.get(host) or {}
            mdns = mdns_devices.get(host) or {}
            upnp = upnp_devices.get(host) or {}
            snmp = snmp_devices.get(host, {})

            device_info = {
                **netbios,
                **mdns,
                **upnp,
                **snmp
            }

            vendor = ""
            hostname = ""
            hostname_source = "Unknown"
            model = ""
            device_type = ""
            os_name = ""
            open_ports = ""
            services = ""
            dns_name = ""
            response_time = ""

            original_mac = ""

            if "addresses" in data:
                original_mac = data["addresses"].get("mac", "")

            mac = original_mac.replace(":", "-").upper()
            ip_version = "IPv6" if ":" in host else "IPv4"

            vendor = ""
            vendor_source = "Unknown"

            # IEEE
            if original_mac:
                vendor = lookup_vendor(original_mac)
                if vendor:
                    vendor_lower = vendor.lower()

                    for key, value in VENDOR_MAP.items():
                        if key in vendor_lower:
                            vendor = value
                            break

                    vendor_source = "IEEE OUI"

            # Nmap
            if not vendor and original_mac and "vendor" in data:
                vendor = data["vendor"].get(original_mac, "")
                if vendor:
                    vendor_lower = vendor.lower()

                    for key, value in VENDOR_MAP.items():
                        if key in vendor_lower:
                            vendor = value
                            break

                if vendor:
                    vendor_source = "Nmap"

            # UPnP
            if not vendor and upnp.get("manufacturer"):
                vendor = upnp["manufacturer"]
                vendor_source = "UPnP"

            # mDNS
            if not vendor and mdns.get("manufacturer"):
                vendor = mdns["manufacturer"]
                vendor_source = "mDNS"


            if data.hostnames():
                hostname = data.hostnames()[0].get("name", "")

            if device_info.get("friendlyName"):

                hostname = device_info["friendlyName"]
                hostname_source = "UPnP"

            elif device_info.get("hostname"):

                hostname = device_info["hostname"]

                if mdns.get("hostname"):
                    hostname_source = "mDNS"

                elif netbios.get("hostname"):
                    hostname_source = "NetBIOS"

                else:
                    hostname_source = "Device"

            elif hostname:
                hostname_source = "Nmap"

            elif snmp.get("systemName"):
                hostname = snmp["systemName"]
                hostname_source = "SNMP"

            dns = {
                "hostname": "",
                "aliases": [],
                "addresses": [],
                "success": False
            }

            if not hostname:
                dns = reverse_dns_cache.get(host)

                if dns is None:
                    dns = reverse_dns_lookup(host)
                    reverse_dns_cache[host] = dns

                hostname = dns["hostname"]

                if dns["success"]:
                    hostname_source = "Reverse DNS"

            # Fallback
            if not hostname:
                hostname = host
                hostname_source = "IP Address"

            dns_name = dns["hostname"] if dns["success"] else ""

            workgroup = netbios.get("workgroup", "")

            response = "Unknown"

            try:
                if "times" in data:
                    srtt = data["times"].get("srtt")
                    if srtt is not None:
                        response = f"{srtt/1000:.2f} ms"

            except Exception:
                pass

            raw = "|".join([
                mac,
                upnp.get("udn", ""),
                upnp.get("serial", ""),
                hostname.lower(),
                host
            ])

            if raw.strip():
                endpoint_id = "DEV-" + hashlib.md5(raw.encode()).hexdigest()[:12].upper()
            else:
                endpoint_id = f"DEV-{host.replace('.', '')}"

            os_confidence = "Unknown"
            try:
                os_name = get_os(data)

                try:
                    if data.get("osmatch"):
                        os_confidence = data["osmatch"][0].get("accuracy", 0)
                except Exception:
                    pass

                model = (
                    device_info.get("model")
                    or upnp.get("model")
                    or upnp.get("modelNumber")
                    or upnp.get("friendlyName")
                    or snmp.get("systemDescription")
                    or mdns.get("model")
                    or netbios.get("model")
                    or ""
                )
            except Exception:
                pass

            port_details = get_port_details(data)
            open_ports = get_open_ports(data)
            services = get_services(data)
            classification_text = (
                    f"{os_name} "
                    f"{hostname} "
                    f"{model}"
                ).lower()

            device_type = "Unknown Device"

            for keyword, value in DEVICE_TYPE_MAP.items():

                if keyword in classification_text:
                    device_type = value
                    break

            if upnp.get("deviceType"):
                device_type = upnp["deviceType"]

            elif mdns.get("deviceType"):
                device_type = mdns["deviceType"]

            elif netbios.get("deviceType"):
                device_type = netbios["deviceType"]


            if not vendor:

                vendor = (
                    upnp.get("manufacturer")
                    or mdns.get("manufacturer")
                    or vendor
                )

            if not vendor and hostname:
                text = f"{hostname} {model}".lower()
                for keyword, value in VENDOR_MAP.items():

                    if keyword in text:
                        vendor = value
                        break


            combined_services = set()

            if services:
                combined_services.update(services.split(", "))

            if mdns.get("service"):
                combined_services.add(mdns["service"])

            if upnp.get("serviceType"):
                combined_services.add(upnp["serviceType"])

            if netbios.get("service"):
                combined_services.add(netbios["service"])

            combined_services = [
                s.strip()
                for s in combined_services
                if s.strip()
            ]

            combined_services = sorted(
                combined_services,
                key=str.lower
            )

            service_categories = []

            for service in combined_services:

                s = service.lower()

                if "http" in s:
                    service_categories.append("Web")
                elif "ftp" in s:
                    service_categories.append("File Transfer")
                elif "ssh" in s:
                    service_categories.append("Remote Access")
                elif "printer" in s:
                    service_categories.append("Printing")
                elif "dns" in s:
                    service_categories.append("DNS")
                elif "upnp" in s:
                    service_categories.append("Discovery")

            discovery_sources = []

            if data.state() == "up":
                discovery_sources.append("Nmap")
            if dns["success"]:
                discovery_sources.append("Reverse DNS")
            if netbios:
                discovery_sources.append("NetBIOS")
            if mdns:
                discovery_sources.append("mDNS")
            if upnp:
                discovery_sources.append("UPnP")
            if vendor_source == "IEEE OUI":
                discovery_sources.append("IEEE OUI")
            
            protocol_versions = {}
            if mdns:
                protocol_versions["mDNS"] = "v1"
            if netbios:
                protocol_versions["NetBIOS"] = "NBT"
            if upnp:
                protocol_versions["UPnP"] = "SSDP/1.0"

            confidence = 20
            if dns["success"]:
                confidence += 10
            if netbios:
                confidence += 15
            if mdns:
                confidence += 20
            if upnp:
                confidence += 25
            if vendor:
                confidence += 10
            if model:
                confidence += 10
            if hostname and hostname != host:
                confidence += 10
            if open_ports:
                confidence += 10
            if response_time:
                confidence += 5
            if mac:
                confidence += 5
            if device_type != "Unknown Device":
                confidence += 5
            if vendor_source == "IEEE OUI":
                confidence += 10
            if snmp.get("snmpEnabled"):
                confidence += 25
            elif vendor_source == "Nmap":
                confidence += 5
            confidence = min(confidence, 100)

            if confidence >= 90:
                rank = "Excellent"
            elif confidence >= 70:
                rank = "Good"
            elif confidence >= 50:
                rank = "Fair"
            else:
                rank = "Low"

            protocol_count = sum([
                bool(dns["success"]),
                bool(netbios),
                bool(mdns),
                bool(upnp),
                #bool(snmp),
                snmp.get("snmpEnabled", False)
            ])

            if "Printer" in device_type:
                category = "Peripheral"
            elif "Router" in device_type:
                category = "Infrastructure"
            elif "Switch" in device_type:
                category = "Infrastructure"
            elif "Firewall" in device_type:
                category = "Security"
            elif "Camera" in device_type:
                category = "Surveillance"
            elif "TV" in device_type:
                category = "Entertainment"
            else:
                category = "Endpoint"

            status = "Online" if data.state() == "up" else "Offline"

            last_protocol = ""

            if upnp:
                last_protocol = "UPnP"
            elif mdns:
                last_protocol = "mDNS"
            elif netbios:
                last_protocol = "NetBIOS"
            else:
                last_protocol = "Nmap"

            if snmp.get("snmpEnabled"):
                discovery_sources.append("SNMP")
                protocol_versions["SNMP"] = "v2c"

            device_signature = hashlib.sha1(
                (
                    host +
                    mac +
                    model +
                    vendor
                ).encode()
            ).hexdigest()

            device = {
                "endpointId": endpoint_id,
                "hostname": hostname,
                "hostnameSource": hostname_source,
                "workgroup": workgroup,
                "manufacturer": vendor,
                "manufacturerSource": vendor_source,
                "model": model if model else "Unknown",
                "modelNumber": upnp.get("modelNumber", ""),
                "friendlyName": upnp.get("friendlyName", ""),
                "ip": host,
                "mac": mac,
                "ipVersion": ip_version,
                "firmware": "Unknown",
                "software": "Unknown",
                "hardware": "Unknown",
                "serial": "Unknown",
                "deviceType": device_type,
                "dnsName": dns_name,
                "reverseDns": dns_name,
                "reverseDnsResolved": dns["success"],
                "dnsAliases": dns["aliases"],
                "dnsAddresses": dns["addresses"],
                "connectionType": connection_type if host==socket.gethostbyname(socket.gethostname()) else "Unknown",
                "wifiBand": "Unknown",
                "wifiChannel": "Unknown",
                "ssid": "Unknown",
                "rssi": "Unknown",
                "uptime": "Unknown",
                "scanTime": scan_time,
                "responseTime": response,
                "lastSeen": scan_time,
                "lastBoot": "Unknown",
                "active": data.state() == "up",
                "discoveryTimestamp": int(time.time()),
                "operatingSystem": os_name if os_name else "Unknown",
                "openPorts": open_ports,
                "portDetails": port_details,
                "openPortCount": len(open_ports.split(", ")) if open_ports else 0,
                "services": ", ".join(combined_services),
                "serviceCount": len(combined_services),
                "serviceCategories": sorted(set(service_categories)),
                "friendlyName": upnp.get("friendlyName", ""),
                "modelNumber": upnp.get("modelNumber", ""),
                "serial": upnp.get("serial", ""),
                "presentationURL": upnp.get("presentationURL", ""),
                "manufacturerURL": upnp.get("manufacturerURL", ""),
                "udn": upnp.get("udn", ""),
                "discoverySource": ", ".join(discovery_sources),
                "confidence": confidence,
                "rank": rank,
                "netbios": netbios,
                "mdns": mdns,
                "upnp": upnp,
                "protocolVersions": protocol_versions,
                "protocolCount": protocol_count,
                "scanDuration": 0,
                "status": status,
                "category": category,
                "deviceSignature": device_signature,
                "firstDiscovered": scan_time,
                "lastDiscovered": scan_time,
                "mdnsAvailable": bool(mdns),
                "netbiosAvailable": bool(netbios),
                "upnpAvailable": bool(upnp),
                "lastDiscoveryProtocol": last_protocol,
                "primaryDiscoveryProtocol": discovery_sources[0] if discovery_sources else "",
                "osConfidence": os_confidence,
                "nmap": {
                    "hostnames": data.hostnames(),
                    "state": data.state(),
                    "vendor": data.get("vendor", {}),
                    "addresses": data.get("addresses", {})
                },
                "confidenceReason": {
                    "netbios": bool(netbios),
                    "mdns": bool(mdns),
                    "upnp": bool(upnp),
                    "vendor": bool(vendor),
                    "model": bool(model),
                    "hostname": hostname != host,
                    "ports": bool(open_ports)
                },
                "snmpEnabled": snmp.get("snmpEnabled", False),
                "snmpVersion": snmp.get("snmpVersion",""),
                "systemDescription": snmp.get("systemDescription", ""),
                "systemName": snmp.get("systemName", ""),
                "systemLocation": snmp.get("location", ""),
                "systemContact": snmp.get("contact", ""),
                "systemUptime": snmp.get("uptime", ""),
                "systemObjectId": snmp.get("objectId", "")
                }

            devices.append(device)
            """"
            print(
                f"{host:15} "
                f"{'Online' if data.state()=='up' else 'Offline':8} "
                f"{vendor:20} "
                f"{hostname:20} "
                f"{os_name}"
            )
            """

        except Exception as e:
            print(f"Unable to scan {host} : {e}")
            traceback.print_exc()

    elapsed = round(time.time() - scan_time, 2)

    if elapsed < 1:
        scan_duration = f"{elapsed*1000:.0f} ms"

    elif elapsed < 60:
        scan_duration = f"{elapsed:.2f} sec"

    else:
        minutes = int(elapsed // 60)
        seconds = elapsed % 60

        scan_duration = f"{minutes} min {seconds:.2f} sec"
    
    for device in devices:
        device["scanDuration"] = scan_duration

    print(f"Total Scan Duration : {scan_duration}")
    
    print(f"Scan Completed : {len(devices)} device(s) found.")

    online = sum(1 for d in devices if d["active"])

    print("=" * 60)
    print(f"Online Devices : {online}")
    print(f"Offline Devices: {len(devices) - online}")
    print("=" * 60)

    return devices