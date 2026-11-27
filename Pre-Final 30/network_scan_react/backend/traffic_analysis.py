import os
import glob
import json
import time
import pyshark
import asyncio
import ipaddress
import traceback
import threading
from collections import Counter #, defaultdict
from datetime import datetime


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TRACE_FOLDER = os.path.join(BASE_DIR, "pcapTrace")
CACHE_FOLDER = os.path.join(BASE_DIR, "pcapCache")

os.makedirs(CACHE_FOLDER, exist_ok=True)

HISTORY_FILE = os.path.join(
    CACHE_FOLDER,
    "traffic_history.json"
)

CACHE_FILE = os.path.join(
    CACHE_FOLDER,
    "traffic_analysis.json"
)

analysis_lock = threading.Lock()

from datetime import datetime

def get_packet_timestamp(packet):

    raw = getattr(packet, "sniff_timestamp", None)

    if raw is None:
        raw = packet.sniff_time

    raw = str(raw)

    # Unix epoch
    if raw.replace(".", "", 1).isdigit():
        return float(raw)

    # ISO-8601
    raw = raw.replace("Z", "")

    if "." in raw:
        head, frac = raw.split(".", 1)
        raw = f"{head}.{frac[:6]}"

    return datetime.fromisoformat(raw).timestamp()

def is_internal_ip(ip):

    try:

        addr = ipaddress.ip_address(ip)

        return (
            addr.is_private or
            addr.is_link_local or
            addr.is_loopback
        )

    except Exception:
        return False

def analyse_pcap(new_pcap=None):
    start_time = time.perf_counter()
    """
    print("=" * 60)
    print("Traffic Analysis Started")
    print("=" * 60)
    """

    with analysis_lock:
        try:

            try:
                asyncio.get_running_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            
            if new_pcap:
                pcaps = [new_pcap]
            else:
                pcaps = sorted(
                    glob.glob(os.path.join(TRACE_FOLDER, "*.pcapng")),
                    key=os.path.getmtime
                )

            processed_history = load_history()

            current_files = {
                os.path.basename(file)
                for file in pcaps
            }

            cached = load_cached_analysis()
            """
            print("=" * 60)
            print("Existing Cache")
            print(f"Total Packets : {cached.get('totalPackets', 0)}")
            print(f"Total Bytes   : {cached.get('totalBytes', 0)}")
            print("=" * 60)
            """
            processed_history.intersection_update(current_files)
            
            if not pcaps:
                return {
                    "status": "ERROR",
                    "message": "No PCAP files found."
                }
            """
            print("=" * 60)
            print("Traffic Analysis")
            print(f"Total PCAP Files : {len(pcaps)}")
            print("=" * 60)
            """
            #print("=" * 60)
            #print("Traffic Analysis")
            #print("PCAP File :", latest_pcap)
            #print("=" * 60)

            #protocol_counter = Counter()
            protocol_counter = Counter(cached.get("protocols", {}))
            source_counter = Counter({item["ip"]: item["packets"] 
                                        for item in cached.get("topTalkers", [])
                                    })
            destination_counter = Counter({item["ip"]: item["packets"]
                                            for item in cached.get("topReceivers", [])
                                        })
            source_bytes = Counter({item["ip"]: item["bytes"]
                                        for item in cached.get("topTalkers", [])
                                    })
            destination_bytes = Counter({item["ip"]: item["bytes"]
                                            for item in cached.get("topReceivers", [])
                                        })
            second_counter = Counter()
            source_port_counter = Counter()
            destination_port_counter = Counter()
            connection_counter = Counter()
            connection_bytes = Counter()
            conversation_counter = Counter()
            conversation_bytes = Counter()
            conversation_protocol = Counter()
            conversation_ports = Counter()

            traffic_direction = cached.get(
                "internalExternalTraffic",
                {}
            )

            internal_internal = traffic_direction.get(
                "internalInternal",
                {}
            )

            internal_external = traffic_direction.get(
                "internalExternal",
                {}
            )

            external_internal = traffic_direction.get(
                "externalInternal",
                {}
            )

            external_external = traffic_direction.get(
                "externalExternal",
                {}
            )

            internal_internal_packets = internal_internal.get(
                "packets", 0
            )

            internal_external_packets = internal_external.get(
                "packets", 0
            )

            external_internal_packets = external_internal.get(
                "packets", 0
            )

            external_external_packets = external_external.get(
                "packets", 0)


            internal_internal_bytes = internal_internal.get(
                "bytes", 0
            )

            internal_external_bytes = internal_external.get(
                "bytes", 0
            )

            external_internal_bytes = external_internal.get(
                "bytes", 0
            )

            external_external_bytes = external_external.get(
                "bytes", 0
            )

            packet_sizes = []
            first_time = None
            last_time = None
            total_packets = cached.get("totalPackets", 0)
            total_bytes = cached.get("totalBytes", 0)
            ratio = cached.get("uploadDownloadRatio", {})
            upload_bytes = ratio.get("uploadBytes", 0)
            download_bytes = ratio.get("downloadBytes", 0)

            #files_to_process = pcaps[:-1] if len(pcaps) > 1 else pcaps
            files_to_process = []

            for file in pcaps:
                #print(f"Checking : {os.path.basename(file)}")
                filename = os.path.basename(file)
                if filename not in processed_history:
                    #print(f"New PCAP Found : {filename}")
                    files_to_process.append(file)
                else:
                    print(f"Already Analysed : {filename}")

            if not files_to_process:

                print("=" * 60)
                print("No new PCAP files found.")

                if os.path.exists(CACHE_FILE):

                    print("Using Existing Cache")
                    cached_analysis = load_cached_analysis()

                    print("Connection Matrix Entries :",
                        len(cached_analysis.get("connectionMatrix", [])))

                    print("Top Conversations :",
                        len(cached_analysis.get("topConversations", [])))

                    return cached_analysis

                    #return load_cached_analysis()


                print("No Cache Exists.")
                print("Returning Empty Analysis.")

                return {
                    "status": "SUCCESS",
                    "totalPackets": 0,
                    "totalBytes": 0,
                    "protocols": {}
                }

            skipped_files = 0
            processed_files = 0

            for pcap_file in files_to_process:

                #print("-" * 60)
                #print("Processing :", os.path.basename(pcap_file))
                #print("-" * 60)

                capture = None

                try:

                    if os.path.getsize(pcap_file) == 0:
                        skipped_files += 1
                        print(f"Skipping Empty PCAP : {os.path.basename(pcap_file)}")
                        continue

                    capture = pyshark.FileCapture(
                        pcap_file,
                        keep_packets=False,
                        use_json=True
                    )

                    #print("Reading packets...")

                    for packet in capture:

                        total_packets += 1

                        # ---------------- Protocol ----------------

                        protocol = getattr(packet, "highest_layer", "UNKNOWN")
                        protocol = protocol.upper() if protocol else "UNKNOWN"

                        if protocol in ("DATA", "ETH", "FRAME"):
                            protocol = "OTHER"

                        protocol_counter[protocol] += 1

                        # ---------------- Source / Destination ----------------

                        if hasattr(packet, "ip"):
                            src = getattr(packet.ip, "src", "Unknown")
                            dst = getattr(packet.ip, "dst", "Unknown")

                        elif hasattr(packet, "ipv6"):
                            src = getattr(packet.ipv6, "src", "Unknown")
                            dst = getattr(packet.ipv6, "dst", "Unknown")

                        else:
                            src = "Unknown"
                            dst = "Unknown"

                        src_port = "-"
                        dst_port = "-"

                        try:

                            if hasattr(packet, "tcp"):

                                src_port = getattr(packet.tcp, "srcport", "-")
                                dst_port = getattr(packet.tcp, "dstport", "-")

                            elif hasattr(packet, "udp"):

                                src_port = getattr(packet.udp, "srcport", "-")
                                dst_port = getattr(packet.udp, "dstport", "-")

                        except Exception:

                            pass

                        if src_port != "-":
                            source_port_counter[str(src_port)] += 1

                        if dst_port != "-":
                            destination_port_counter[str(dst_port)] += 1

                        source_counter[src] += 1
                        destination_counter[dst] += 1

                        # ---------------- Packet Length ----------------

                        try:
                            length = int(getattr(packet, "length", 0))
                        except Exception as e:
                            print(f"Length Error : {e}")
                            length = 0

                        packet_sizes.append(length)

                        connection_key = (src, dst)
                        connection_counter[connection_key] += 1
                        total_bytes += length
                        connection_bytes[connection_key] += length
                        source_bytes[src] += length
                        destination_bytes[dst] += length

                        if src == "Unknown" or dst == "Unknown":
                            continue

                        src_internal = is_internal_ip(src)
                        dst_internal = is_internal_ip(dst)

                        if src_internal and dst_internal:

                            internal_internal_packets += 1
                            internal_internal_bytes += length

                        elif src_internal and not dst_internal:

                            internal_external_packets += 1
                            internal_external_bytes += length

                        elif not src_internal and dst_internal:

                            external_internal_packets += 1
                            external_internal_bytes += length

                        else:

                            external_external_packets += 1
                            external_external_bytes += length


                        # Conversation Statistics (bidirectional)

                        conversation_key = tuple(sorted([src, dst]))

                        conversation_counter[conversation_key] += 1
                        conversation_bytes[conversation_key] += length

                        conversation_protocol[(conversation_key, protocol)] += 1

                        if dst_port != "-":
                            conversation_ports[(conversation_key, str(dst_port))] += 1

                        # ---------------- Timestamp ----------------

                        try:
                            ts = get_packet_timestamp(packet)

                            if first_time is None:
                                first_time = ts

                            last_time = ts

                            second_counter[int(ts)] += 1

                        except Exception as e:
                            print(f"Timestamp Error : {e}")

                        # ---------------- Upload / Download ----------------

                        if src.startswith(("192.168.", "10.", "172.")):
                            upload_bytes += length
                        else:
                            download_bytes += length

                    processed_files += 1

                    #print(f"Added To History : {os.path.basename(pcap_file)}")

                    processed_history.add(os.path.basename(pcap_file))

                except Exception as e:
                    skipped_files += 1
                    print("=" * 60)
                    print(f"Error processing : {os.path.basename(pcap_file)}")
                    traceback.print_exc()
                    print("=" * 60)

                finally:

                    if capture is not None:
                        capture.close()

                #print(f"Processed : {os.path.basename(pcap_file)}")
                #print(f"Running Total Packets : {total_packets}")
                
            try:

                loop = asyncio.get_event_loop()
                if not loop.is_closed():
                    loop.close()

            except Exception as e:
                print(f"Loop close warning: {e}")    
            
            if first_time is None or last_time is None:

                print("Warning : No valid timestamps found.")
                duration = 1
            else:
                duration = max(last_time - first_time, 1)
            avg_size = (round(total_bytes / total_packets, 2) if total_packets else 0)
            largest = max(
                cached.get("largestPacket", 0),
                max(packet_sizes) if packet_sizes else 0
            )
            cached_smallest = cached.get("smallestPacket", 0)
            if packet_sizes:
                if cached_smallest == 0:
                    smallest = min(packet_sizes)
                else:
                    smallest = min(cached_smallest, min(packet_sizes))
            else:
                smallest = cached_smallest
            packet_rate = round(total_packets / duration, 2)
            throughput = round((total_bytes * 8) / duration / 1000000, 2)
            peak_second = ""
            peak_packets = 0

            if second_counter:
                sec, peak_packets = second_counter.most_common(1)[0]
                peak_second = datetime.fromtimestamp(sec).strftime("%d-%b-%Y %H:%M:%S")

            cached_peak = cached.get("peakTrafficPackets", 0)

            if cached_peak > peak_packets:
                peak_packets = cached_peak
                peak_second = cached.get("peakTrafficTime", "")

            total_ud = upload_bytes + download_bytes

            if total_ud == 0:

                upload_percent = 0
                download_percent = 0

            else:

                upload_percent = round(upload_bytes * 100 / total_ud, 1)
                download_percent = round(download_bytes * 100 / total_ud, 1)

            '''
            print("=" * 60)
            print("Traffic Analysis Summary")
            print("=" * 60)

            print("Analysis Mode      :", "Historical")
            print("Processed Files    :", processed_files)
            print("PCAP Files         :", len(files_to_process))

            print("-" * 60)

            print("Total Packets      :", total_packets)
            print("Total Bytes        :", total_bytes)
            print("Protocols          :", len(protocol_counter))

            print("-" * 60)

            print("Protocol Distribution")
            for proto, count in protocol_counter.most_common():
                print(f"{proto:12} : {count}")

            print("-" * 60)

            print("Top Talkers        :", len(source_counter))
            for ip, packets in source_counter.most_common(10):
                print(
                    f"{ip:20} "
                    f"Packets:{packets:8} "
                    f"Bytes:{source_bytes[ip]}"
                )
            '''

            analysis_time = round(time.perf_counter() - start_time, 2)

            '''
            print("-" * 60)

            print("Top Receivers      :", len(destination_counter))
            for ip, packets in destination_counter.most_common(10):
                print(
                    f"{ip:20} "
                    f"Packets:{packets:8} "
                    f"Bytes:{destination_bytes[ip]}"
                )

            print("-" * 60)

            print("Capture Duration   :", round(duration, 2), "sec")
            print("Packet Rate        :", packet_rate, "packets/sec")
            print("Throughput         :", throughput, "Mbps")

            print("-" * 60)

            print("Average Packet     :", avg_size, "Bytes")
            print("Largest Packet     :", largest, "Bytes")
            print("Smallest Packet    :", smallest, "Bytes")

            print("-" * 60)

            print("Peak Traffic Time  :", peak_second)
            print("Peak Packets/Sec   :", peak_packets)

            print("-" * 60)

            print("Upload             :", upload_percent, "%")
            print("Download           :", download_percent, "%")

            print("=" * 60)
            '''

            print("=" * 60)
            print("Top Conversations :", len(conversation_counter))
            print("Connection Matrix :", len(connection_counter))
            print("=" * 60)

            result = {

                "analysisMode": "Historical",
                "pcapFilesAnalysed": len(files_to_process),
                "oldestCapture": os.path.basename(pcaps[0]),
                "newestCapture": os.path.basename(pcaps[-1]),
                "captureDuration": round(duration, 2),
                "peakTrafficPackets": peak_packets,
                "totalPackets": total_packets,
                "totalBytes": total_bytes,
                "protocols": dict(protocol_counter),

                "topSourcePorts": [
                    {
                        "port": port,
                        "packets": count
                    }
                    for port, count in source_port_counter.most_common(20)
                ],

                "topDestinationPorts": [
                    {
                        "port": port,
                        "packets": count
                    }
                    for port, count in destination_port_counter.most_common(20)
                ],

                "topTalkers": [
                    {
                        "ip": ip,
                        "hostname": "-",
                        "packetCount": source_counter[ip],
                        "packets": source_counter[ip],
                        "bytes": source_bytes[ip],
                        "percentage": round(
                            (source_counter[ip] * 100 / total_packets),
                            2
                        ) if total_packets else 0
                    }
                    for ip, _ in source_counter.most_common(10)
                ],

                "topReceivers": [
                    {
                        "ip": ip,
                        "hostname": "-",
                        "packetCount": destination_counter[ip],
                        "packets": destination_counter[ip],
                        "bytes": destination_bytes[ip],
                        "percentage": round(
                            (destination_counter[ip] * 100 / total_packets),
                            2
                        ) if total_packets else 0
                    }
                    for ip, _ in destination_counter.most_common(10)
                ],

                "connectionMatrix": [
                    {
                        "source": src,
                        "destination": dst,
                        "packets": connection_counter[(src, dst)],
                        "bytes": connection_bytes[(src, dst)]
                    }

                    for (src, dst), _
                    in connection_counter.most_common(20)

                ],

                "topConversations": [
                    {
                        "endpointA": ep1,
                        "endpointB": ep2,
                        "packets": conversation_counter[(ep1, ep2)],
                        "bytes": conversation_bytes[(ep1, ep2)],
                        "averagePacketSize": round(
                            conversation_bytes[(ep1, ep2)] /
                            conversation_counter[(ep1, ep2)],
                            2
                        ),
                        "protocol": max(
                            (
                                p for (k, p) in conversation_protocol
                                if k == (ep1, ep2)
                            ),
                            key=lambda proto:
                                conversation_protocol[((ep1, ep2), proto)],
                            default="-"
                        ),
                        "topPort": max(
                            (
                                p for (k, p) in conversation_ports
                                if k == (ep1, ep2)
                            ),
                            key=lambda port:
                                conversation_ports[((ep1, ep2), port)],
                            default="-"
                        ),
                        "trafficPercent": round(
                            conversation_counter[(ep1, ep2)] * 100 /
                            total_packets,
                            2
                        )
                    }

                    for (ep1, ep2), _
                    in conversation_counter.most_common(20)
                ],

                "internalExternalTraffic": {

                "internalInternal": {
                    "packets": internal_internal_packets,
                    "bytes": internal_internal_bytes
                },

                "internalExternal": {
                    "packets": internal_external_packets,
                    "bytes": internal_external_bytes
                },

                "externalInternal": {
                    "packets": external_internal_packets,
                    "bytes": external_internal_bytes
                },

                "externalExternal": {
                    "packets": external_external_packets,
                    "bytes": external_external_bytes
                }

            },

                "averagePacketSize": avg_size,
                "largestPacket": largest,
                "smallestPacket": smallest,
                "packetRate": packet_rate,
                "throughputMbps": throughput,
                "peakTrafficTime": peak_second,
                "uploadDownloadRatio": {
                    "upload": upload_percent,
                    "download": download_percent,
                    "uploadBytes": upload_bytes,
                    "downloadBytes": download_bytes
                },
                "analysisGeneratedAt": datetime.now().strftime("%d-%b-%Y %H:%M:%S"),
                "analysisExecutionTime": analysis_time,
                "processedFiles": processed_files,
                "skippedFiles": skipped_files,
                "lastAnalysedFile": (
                    os.path.basename(files_to_process[-1])
                    if files_to_process
                    else ""
                )

            }

            temp_file = CACHE_FILE + ".tmp"

            try:
                #print("=" * 60)
                #print("Writing Cache")
                #print(f"Packets : {total_packets}")
                #print(f"Bytes   : {total_bytes}")
                #print("=" * 60)

                with open(temp_file, "w") as fp:
                    json.dump(result, fp, indent=4)

                os.replace(temp_file, CACHE_FILE)
                #print("traffic_analysis.json Updated")

                save_history(processed_history)
                #print("History Updated")

            except Exception as e:

                print("=" * 60)
                print("Failed to write traffic_analysis.json")
                print(e)
                traceback.print_exc()
                print("=" * 60)

                raise

            #print("-" * 60)
            #print("Analysis Time      :", analysis_time, "sec")
            #print("=" * 60)

            # print("=" * 80)
            # print("PORT STATISTICS")
            # print("=" * 80)

            # print("\nSource Port Counter")
            # print(source_port_counter)

            # print("\nDestination Port Counter")
            # print(destination_port_counter)

            # print("\nTop Source Ports")
            # print(source_port_counter.most_common(20))

            # print("\nTop Destination Ports")
            # print(destination_port_counter.most_common(20))

            # print("=" * 80)

            return result

        except Exception as e:

                traceback.print_exc()

                return {
                    "status": "ERROR",
                    "message": str(e)
                }
        
def load_history():

    if not os.path.exists(HISTORY_FILE):
        return set()

    try:
        with open(HISTORY_FILE, "r") as fp:
            return set(json.load(fp))

    except Exception:
        return set()

def save_history(history):

    with open(HISTORY_FILE, "w") as fp:
        json.dump(
            sorted(list(history)),
            fp,
            indent=4
        )

def load_cached_analysis():

    if not os.path.exists(CACHE_FILE):
        return {}

    try:
        with open(CACHE_FILE, "r") as fp:
            return json.load(fp)
    except Exception:
        return {}