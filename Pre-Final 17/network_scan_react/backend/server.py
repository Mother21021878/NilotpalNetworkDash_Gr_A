import os
import shutil
import json
import traceback
import threading
import time
import platform
from flask_cors import CORS
from flask import Flask, jsonify, request
from risk_engine import risk_engine
from scanner import *
from packet_capture import start_capture, get_packets
from datetime import datetime
from threading import Lock
from deep_analysis import analyze_packet_window
from packet_capture import get_packet_context

app = Flask(__name__)
CORS(app)

SERVER_START = datetime.now()
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

TRAFFIC_PCAPTRACE_FOLDER = os.path.join(
    BASE_DIR,
    "pcapTrace"
)

TRAFFIC_ANALYSIS_CACHE = os.path.join(
    BASE_DIR,
    "pcapCache",
    "traffic_analysis.json"
)

TRAFFIC_ANALYSIS_HISTORY = os.path.join(
    BASE_DIR,
    "pcapCache",
    "traffic_history.json"
)

RISK_ANALYSIS_CACHE = os.path.join(
    BASE_DIR,
    "pcapCache",
    "risk_analysis.json"
)

RISK_ANALYSIS_HISTORY = os.path.join(
    BASE_DIR,
    "pcapCache",
    "risk_history.json"
)


latest_devices = []
latest_dashboard = {}
last_scan_time = None
last_scan_duration = 0

device_lock = Lock()

SCAN_INTERVAL = 1800
API_VERSION = "1.0.0"

HOST = "127.0.0.1"
PORT = 5000
API_VERSION = "1.0.0"
BUILD_VERSION = "2026-07-06"

ENABLE_BACKGROUND_SCAN = True
ENABLE_PACKET_CAPTURE = True

def build_dashboard_summary(devices):

    summary = {

        "totalDevices": 0,
        "onlineDevices": 0,
        "offlineDevices": 0,
        "routers": 0,
        "switches": 0,
        "servers": 0,
        "workstations": 0,
        "printers": 0,
        "iotDevices": 0,
        "criticalRisk": 0,
        "highRisk": 0,
        "mediumRisk": 0,
        "lowRisk": 0,
        "scanDuration": "",
        "lastScanTime": ""
    }

    if not devices:
        return summary

    summary["totalDevices"] = len(devices)

    for device in devices:

        if device.get("active"):
            summary["onlineDevices"] += 1
        else:
            summary["offlineDevices"] += 1

        dtype = (
            device.get("deviceType") or ""
        ).lower()

        if "router" in dtype: summary["routers"] += 1

        elif "switch" in dtype: summary["switches"] += 1

        elif "server" in dtype: summary["servers"] += 1

        elif "printer" in dtype: summary["printers"] += 1

        elif ( "pc" in dtype or "laptop" in dtype or "desktop" in dtype or "windows" in dtype or "linux" in dtype ):
            summary["workstations"] += 1

        else:
            summary["iotDevices"] += 1

        risk = device.get("deviceRiskLevel", "")

        if risk == "Critical": summary["criticalRisk"] += 1

        elif risk == "High": summary["highRisk"] += 1

        elif risk == "Medium": summary["mediumRisk"] += 1

        else:
            summary["lowRisk"] += 1

    summary["scanDuration"] = devices[0].get("scanDuration", "")
    summary["lastScanTime"] = last_scan_time

    return summary

def sort_devices(devices):

    devices.sort(
        key=lambda d: tuple(
            map(
                int,
                d["ip"].split(".")
            )
        )
    )

    return devices

def perform_network_scan():

    start = time.time()
    devices = scan_network() or []
    devices = sort_devices(devices)
    scan_time = datetime.now().strftime("%d-%b-%Y %I:%M:%S %p")
    duration = round(time.time() - start, 2)

    return devices, scan_time, duration

# Initial device scan
try:
    with device_lock:

        latest_devices, last_scan_time, last_scan_duration = perform_network_scan()
        latest_dashboard = build_dashboard_summary(latest_devices)
    
except Exception as e:
    print(f"Initial network scan failed: {e}")
    print(f"[{datetime.now()}] Scan failed: {e}")
    traceback.print_exc()
    latest_devices = []
    last_scan_time = None
    latest_dashboard = build_dashboard_summary([])

# Live Packet Capture API
# Returns the most recently captured network packets.
@app.route("/packets")
def packets():

    try:
        packets = get_packets()

        return jsonify({
            "status":"SUCCESS",
            "count":len(packets),
            "packets":packets
        })

    except Exception as e:
        traceback.print_exc()

        return jsonify({
            "status":"ERROR",
            "message":str(e)
        }),500

# Health Check API
@app.route("/")
def home():

    uptime = datetime.now() - SERVER_START

    with device_lock:
        device_count = len(latest_devices)
        scan_time = last_scan_time

    return jsonify({
        "status": "UP",
        "service": "Network Monitoring API",
        "version": API_VERSION,
        "message": "API Server is running successfully.",
        "uptime": str(uptime).split(".")[0],
        "host": HOST,
        "port": PORT,
        "scanInterval": SCAN_INTERVAL,
        "lastScan": scan_time,
        "deviceCount": device_count,
        "apis": [
            "/scan",
            "/devices",
            "/statistics",
            "/packets",
            "/device/<ip>",
            "/traffic-analysis",
            "/risk-analysis",
            "/ai/analyze_packet",
            "/ping",
            "/version"
        ]
    })

def build_devices_response():

    dashboard = latest_dashboard or build_dashboard_summary(
        latest_devices
    )

    return {
        "status": "SUCCESS",
        "count": len(latest_devices),
        "scanTime": last_scan_time,
        "duration": last_scan_duration,
        "dashboard": dashboard,
        "devices": latest_devices
    }

# Scan Network API
@app.route('/scan', methods=['GET'])
def scan():

    global latest_devices, last_scan_time, last_scan_duration

    try:
        with device_lock:
            latest_devices, last_scan_time, last_scan_duration = perform_network_scan()
            global latest_dashboard

            latest_dashboard = build_dashboard_summary(
                latest_devices
            )
            duration = last_scan_duration

        return jsonify(
            build_devices_response()
        )

    except Exception as e:
        print(f"[{datetime.now()}] Scan failed: {e}")
        traceback.print_exc()

        return jsonify({
            "status": "ERROR",
            "message": str(e)
        }), 500

# Get Devices API
# Returns the list of devices discovered during the most recent network scan.
# Each device includes details such as IP address, MAC address, hostname,
# device name, model, and other available information.
@app.route('/devices', methods=['GET'])
def get_devices():

    with device_lock:

        return jsonify(
            build_devices_response()
        )

# Create Device API
# Creates a new device entry.
# Accepts device information in JSON format through the request body
# and returns a confirmation message along with the received data.
@app.route('/device', methods=['POST'])
def create_device():

    data = request.json

    return jsonify({
        "status":"SUCCESS",
        "message":"Device Created",
        "device":data
    })

def background_scan():

    global latest_devices
    global last_scan_time
    global last_scan_duration

    # Wait before first background scan
    time.sleep(SCAN_INTERVAL)

    while True:

        try:
            start = time.time()
            with device_lock:
                latest_devices, last_scan_time, last_scan_duration = perform_network_scan()
                global latest_dashboard

                latest_dashboard = build_dashboard_summary(
                    latest_devices
                )

        except Exception as e:
            print(f"[{datetime.now()}] Scan failed: {e}")
            traceback.print_exc()

        elapsed = time.time() - start
        time.sleep(max(1, SCAN_INTERVAL - elapsed))

@app.route("/topology", methods=["GET"])
def get_topology():
    topology = build_network_topology(latest_devices)
    return jsonify(topology)
    #return jsonify(build_network_topology(latest_devices))

@app.route("/statistics")
def statistics():

    with device_lock:

        online = sum(
            1
            for d in latest_devices
            if d.get("active")
        )

        offline = len(latest_devices) - online

        manufacturer_stats = {}
        os_stats = {}
        discovery_stats = {}
        port_stats = {}
        service_stats = {}
        performance_stats = {}
        protocol_stats = {}

        for device in latest_devices:

            manufacturer = (
                device.get("manufacturer")
                or "Unknown"
            ).strip()

            manufacturer_stats[manufacturer] = (
                manufacturer_stats.get(manufacturer, 0) + 1
            )

            operating_system = (
                device.get("operatingSystem")
                or "Unknown"
            ).strip()

            os_stats[operating_system] = (
                os_stats.get(operating_system, 0) + 1
            )

            # Discovery Statistics
            discovery_sources = (
                device.get("discoverySource") or ""
            )

            for source in discovery_sources.split(","):
                source = source.strip()

                if source:
                    discovery_stats[source] = (discovery_stats.get(source, 0) + 1)
        
            # Port Statistics
            ports = device.get("openPorts")

            if ports:

                if isinstance(ports, str):
                    ports = ports.split(",")

                for port in ports:
                    port = str(port).strip()

                    if port:
                        port_stats[port] = (port_stats.get(port, 0) + 1)

            # Service Statistics
            services = device.get("services")

            if services:

                if isinstance(services, str):
                    services = services.split(",")

                for service in services:
                    service = service.strip()

                    if service:
                        service_stats[service] = (service_stats.get(service, 0) + 1)


            # Performance Statistics
            response = device.get("responseTime")

            if response:

                try:
                    response = float(
                        str(response).replace("ms", "")
                    )

                    if response < 10:
                        bucket = "< 10 ms"

                    elif response < 25:
                        bucket = "10 - 25 ms"

                    elif response < 50:
                        bucket = "25 - 50 ms"

                    elif response < 100:
                        bucket = "50 - 100 ms"

                    else:
                        bucket = "> 100 ms"

                    performance_stats[bucket] = (performance_stats.get(bucket, 0) + 1)

                except:

                    pass

            # Protocol Statistics
            protocols = set()

            primary_protocol = (device.get("primaryDiscoveryProtocol") or "").strip()
            last_protocol = (device.get("lastDiscoveryProtocol") or "").strip()

            if primary_protocol:
                protocols.add(primary_protocol)

            if last_protocol:
                protocols.add(last_protocol)

            for protocol in protocols:

                protocol_stats[protocol] = (protocol_stats.get(protocol, 0) + 1)

        manufacturers = []

        for name, count in sorted(
            manufacturer_stats.items(),
            key=lambda item: item[1],
            reverse=True
        ):

            manufacturers.append({
                "name": name,
                "count": count
            })

        operating_systems = []
        discoveries = []

        for name, count in sorted(

                discovery_stats.items(),
                key=lambda item: item[1],
                reverse=True):

            discoveries.append({
                "name": name,
                "count": count
            })

        for name, count in sorted(
            os_stats.items(),
            key=lambda item: item[1],
            reverse=True
        ):

            operating_systems.append({
                "name": name,
                "count": count
            })

        ports = []

        for name, count in sorted(
                port_stats.items(),
                key=lambda item: item[1],
                reverse=True):

            ports.append({
                "name": name,
                "count": count
            })

        services = []

        for name, count in sorted(
                service_stats.items(),
                key=lambda item: item[1],
                reverse=True):

            services.append({
                "name": name,
                "count": count
            })

        performance = []

        order = [
            "< 10 ms",
            "10 - 25 ms",
            "25 - 50 ms",
            "50 - 100 ms",
            "> 100 ms"
        ]

        for bucket in order:

            performance.append({
                "name": bucket,
                "count": performance_stats.get(bucket, 0)
            })

        protocols = []

        for name, count in sorted(
                protocol_stats.items(),
                key=lambda item: item[1],
                reverse=True):

            protocols.append({
                "name": name,
                "count": count
            })

        return jsonify({
            "status": "SUCCESS",
            "total": len(latest_devices),
            "online": online,
            "offline": offline,
            "lastScan": last_scan_time,
            "scanDuration": last_scan_duration,
            "manufacturers": manufacturers,
            "operatingSystems": operating_systems,
            "discoveries": discoveries,
            "ports": ports,
            "services": services,
            "performance": performance,
            "protocols": protocols
        })

@app.route("/device/<ip>")
def device(ip):

    with device_lock:

        for d in latest_devices:

            if d.get("ip") == ip:
                return jsonify({
                    "status":"SUCCESS",
                    "device":d
                })

    return jsonify({
        "status":"ERROR",
        "message":"Device not found"
    }),404

@app.route("/ping")
def ping():

    return jsonify({
        "status":"UP",
        "time":datetime.now().strftime("%d-%b-%Y %I:%M:%S %p"),
        "version": API_VERSION
    })

@app.route("/version")
def version():

    return jsonify({
        "status": "SUCCESS",
        "version": API_VERSION,
        "build": BUILD_VERSION,
        "python": platform.python_version()
    })


@app.route("/traffic-analysis", methods=["GET"])
def traffic_analysis():

    try:

        if not os.path.exists(TRAFFIC_ANALYSIS_CACHE):
            return jsonify({
                "status": "ERROR",
                "message": "Traffic Analysis cache not available."
            }), 404

        with open(
            TRAFFIC_ANALYSIS_CACHE,
            "r",
            encoding="utf-8"
        ) as fp:

            result = json.load(fp)

        return jsonify(result)

    except json.JSONDecodeError:
        return jsonify({
            "status": "ERROR",
            "message":
                "Traffic Analysis cache is being updated."
        }),503

    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "status":"ERROR",
            "message":str(e)
        }),500

@app.route("/risk-analysis", methods=["GET"])
def risk_analysis():

    try:
        if not os.path.exists(RISK_ANALYSIS_CACHE):
            return jsonify({
                "status":"ERROR",
                "message":"Risk Analysis cache not available."
            }),404

        with open(RISK_ANALYSIS_CACHE, "r", encoding="utf-8") as fp:
            data = json.load(fp)
        return jsonify(data)

    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "status":"ERROR",
            "message":str(e)
        }),500

@app.route("/deep-analysis", methods=["POST"])
def deep_analysis():

    try:
        request_data = request.get_json()
        packet_number = request_data.get("packetNumber")
        packets = get_packets()
        packet_window = get_packet_context(
            packets,
            packet_number
        )

        response = analyze_packet_window(packet_window)
        analysis = response
        #print("=" * 80)
        #print("Deep Analysis Response")
        #print(analysis)
        #print(type(analysis))
        #print("=" * 80)

        return jsonify({
            "status": "SUCCESS",
            "analysis": analysis
        })

    except Exception as ex:
        import traceback
        traceback.print_exc()

        return jsonify({
            "status": "ERROR",
            "message": str(ex)
        }), 500

@app.route("/ai/analyze_packet", methods=["POST"])
def analyze_packet():

    try:
        packet = request.get_json(force=True)
        if not packet:
            return jsonify({
                "status": "ERROR",
                "message": "Packet data not received."
            }),400

          # Category Information
        category_result = {
            "category":
                packet.get("category","Unknown"),
            "baseRisk":
                int(packet.get("riskScore",0))

        }

   
        # AI Risk Engine
        risk = risk_engine.calculate(
            packet,
            category_result
        )

        # Update the Live Packet Buffer
        packets = get_packets()

        for live_packet in packets:

            if live_packet.get("number") == packet.get("number"):

                live_packet["riskScore"] = risk["riskScore"]
                live_packet["riskLevel"] = risk["riskLevel"]
                live_packet["confidence"] = risk["confidence"]
                live_packet["category"] = risk["category"]
                live_packet["suspicious"] = risk["suspicious"]

                break

        # AI Explanation
        explanation = []

        if risk["riskLevel"] == "Critical":
            explanation.append(
                "Critical risk packet detected."
            )
        elif risk["riskLevel"] == "High":
            explanation.append(
                "High risk packet detected."
            )
        elif risk["riskLevel"] == "Medium":
            explanation.append(
                "Medium risk packet detected."
            )
        else:
            explanation.append(
                "Low risk packet."
            )

        # External Destination
        destination = str(
            packet.get(
                "destination",
                ""
            )
        )

        if destination and not (
            destination.startswith("10.")
            or
            destination.startswith("172.")
            or
            destination.startswith("192.168.")
        ):

            explanation.append(
                "Traffic is leaving the private network."
            )


        # Large Packet
        if int(packet.get("length",0)) > 1400:
            explanation.append(
                "Large packet detected."
            )

        # Final Response
        return jsonify({
        "status": "SUCCESS",
        "packetNumber": packet.get("number"),
        "analysis": {
            **risk,
            "category": category_result["category"],
            "ai": " ".join(explanation),
            "protocol": packet.get("protocol"),
            "transport": packet.get("transport"),
            "length": packet.get("length"),
            "source": packet.get("source"),
            "destination": packet.get("destination"),
            "sourcePort": packet.get("sourcePort"),
            "destinationPort": packet.get("destinationPort")
        }
    })

    except Exception as ex:
        traceback.print_exc()
        return jsonify({
            "status":"ERROR",
            "message":str(ex)
        }),500

if __name__ == '__main__':
    """
    print("=" * 60)
    print("Network Monitoring API Started")
    print(f"Version              : {API_VERSION}")
    print(f"Host                 : {HOST}")
    print(f"Port                 : {PORT}")
    print(f"Scan Interval        : {SCAN_INTERVAL} sec")
    print(f"Packet Capture       : {ENABLE_PACKET_CAPTURE}")
    print(f"Background Scan      : {ENABLE_BACKGROUND_SCAN}")
    print("=" * 60)
    """
    # Clean all old traffic analysis files
    #if os.path.isdir(TRAFFIC_PCAPTRACE_FOLDER): shutil.rmtree(TRAFFIC_PCAPTRACE_FOLDER)
    #os.makedirs(TRAFFIC_PCAPTRACE_FOLDER, exist_ok=True)
    #if os.path.exists(TRAFFIC_ANALYSIS_CACHE): os.remove(TRAFFIC_ANALYSIS_CACHE)
    #if os.path.exists(TRAFFIC_ANALYSIS_HISTORY): os.remove(TRAFFIC_ANALYSIS_HISTORY)
    #if os.path.exists(RISK_ANALYSIS_CACHE): os.remove(RISK_ANALYSIS_CACHE)
    #if os.path.exists(RISK_ANALYSIS_HISTORY): os.remove(RISK_ANALYSIS_HISTORY)
    
    
    # Start packet capture
    if ENABLE_PACKET_CAPTURE:
        try:
            start_capture()

        except Exception as e:
            print(f"[{datetime.now()}] Packet Capture failed : {e}")
            traceback.print_exc()

    background_thread = None

    if ENABLE_BACKGROUND_SCAN:

        threading.Thread(
            target=background_scan,
            daemon=True,
            name="BackgroundScan"
        ).start()

    try:

        app.run(
            host=HOST,
            port=PORT,
            debug=False
        )

    except KeyboardInterrupt:

        print("\n")
        print("=" * 60)
        print("Stopping Network Monitoring API...")
        print("=" * 60)

    except Exception as ex:

        print(f"Server Error : {ex}")
        traceback.print_exc()

    finally:
        time.sleep(1)
        print("Server shutdown completed.")