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
from scanner import scan_network
from packet_capture import start_capture, get_packets
from datetime import datetime
from threading import Lock
from deep_analysis import analyze_packet_window
from packet_capture import get_packet_context

app = Flask(__name__)
CORS(app)

SERVER_START = datetime.now()
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

TRAFFIC_ANALYSIS_CACHE = os.path.join(
    BASE_DIR,
    "pcapCache",
    "traffic_analysis.json"
)

RISK_ANALYSIS_CACHE = os.path.join(
    BASE_DIR,
    "pcapCache",
    "risk_analysis.json"
)

TRAFFIC_ANALYSIS_HISTORY = os.path.join(
    BASE_DIR,
    "traffic_analysis_history.json"
)

TRAFFIC_PCAPTRACE_FOLDER = os.path.join(
    BASE_DIR,
    "pcapTrace"
)

latest_devices = []
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
    
except Exception as e:
    print(f"Initial network scan failed: {e}")
    print(f"[{datetime.now()}] Scan failed: {e}")
    traceback.print_exc()
    latest_devices = []
    last_scan_time = None

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

# Scan Network API
@app.route('/scan', methods=['GET'])
def scan():

    global latest_devices, last_scan_time, last_scan_duration

    try:
        with device_lock:
            latest_devices, last_scan_time, last_scan_duration = perform_network_scan()
            duration = last_scan_duration
            print(
                f"[{last_scan_time}] "
                f"Manual scan completed "
                f"({len(latest_devices)} devices, {duration} sec)"
            )

        #return jsonify(latest_devices)
        return jsonify({
            "status":"SUCCESS",
            "count":len(latest_devices),
            "scanTime":last_scan_time,
            "duration":duration,
            "devices":latest_devices
        })

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

    #return jsonify(latest_devices)
    with device_lock:
        return jsonify({
            "status": "SUCCESS",
            "count": len(latest_devices),
            "scanTime": last_scan_time,
            "duration": last_scan_duration,
            "devices": latest_devices
        })

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

            print(
                f"[{last_scan_time}] "
                f"Background scan completed "
                f"({len(latest_devices)} devices, "
                f"{last_scan_duration} sec)"
            )

        except Exception as e:
            print(f"[{datetime.now()}] Scan failed: {e}")
            traceback.print_exc()

        elapsed = time.time() - start
        time.sleep(max(1, SCAN_INTERVAL - elapsed))

@app.route("/statistics")
def statistics():

    with device_lock:

        online = sum(
            1 for d in latest_devices
            if d.get("active")
        )

        offline = len(latest_devices) - online

        return jsonify({
            "status":"SUCCESS",
            "total":len(latest_devices),
            "online":online,
            "offline":offline,
            "lastScan":last_scan_time,
            "scanDuration":last_scan_duration
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

        print(f"[{datetime.now()}] " "Traffic Analysis Cache Read" )
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

        analysis = json.loads(
            analyze_packet_window(packet_window)
        )

        return jsonify({
            "status": "SUCCESS",
            "selectedPacket": packet_number,
            "packetCount": len(packet_window),
            "analysis": analysis
        })

    except Exception as ex:

        return jsonify({
            "status": "FAILED",
            "error": str(ex)
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

    print("=" * 60)
    print("Network Monitoring API Started")
    print(f"Version              : {API_VERSION}")
    print(f"Host                 : {HOST}")
    print(f"Port                 : {PORT}")
    print(f"Scan Interval        : {SCAN_INTERVAL} sec")
    print(f"Packet Capture       : {ENABLE_PACKET_CAPTURE}")
    print(f"Background Scan      : {ENABLE_BACKGROUND_SCAN}")
    print("=" * 60)

    # Clean all old traffic analysis files
    #if os.path.exists(TRAFFIC_ANALYSIS_HISTORY): os.remove(TRAFFIC_ANALYSIS_HISTORY)
    #if os.path.exists(TRAFFIC_ANALYSIS_CACHE): os.remove(TRAFFIC_ANALYSIS_CACHE)
    #if os.path.isdir(TRAFFIC_PCAPTRACE_FOLDER): shutil.rmtree(TRAFFIC_PCAPTRACE_FOLDER)
    #os.makedirs(TRAFFIC_PCAPTRACE_FOLDER, exist_ok=True)
    
    # Start packet capture
    if ENABLE_PACKET_CAPTURE:
        try:
            start_capture()

        except Exception as e:
            print(f"[{datetime.now()}] Packet Capture failed : {e}")
            traceback.print_exc()

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
        print("\nStopping Network Monitoring API...")