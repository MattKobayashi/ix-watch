# /// script
# requires-python = ">=3.12,<3.13"
# dependencies = [
#     "fastapi[standard]==0.115.14",
#     "apprise==1.9.3",
#     "scapy==2.6.1",
# ]
# ///
import os
import time
import threading
import asyncio
import logging
import socket
from contextlib import asynccontextmanager
from collections import deque, Counter
from datetime import datetime

import apprise
from apprise import NotifyType
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from scapy.all import sniff, ARP, STP, IP, Ether

# --- Configuration ---
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
load_dotenv()

IX_NAME = os.getenv("IX_NAME", "IX")
INTERFACES = [iface.strip() for iface in os.getenv("INTERFACES", "eth0").split(",")]
ARP_ALERT_THRESHOLD = int(os.getenv("ARP_ALERT_THRESHOLD", 100000))
IP_BROADCAST_ALERT_THRESHOLD = int(os.getenv("IP_BROADCAST_ALERT_THRESHOLD", 100))
TIME_WINDOW_SECONDS = int(os.getenv("TIME_WINDOW_SECONDS", 900))
STP_ALERT_THRESHOLD = int(os.getenv("STP_ALERT_THRESHOLD", 1))
NON_IP_ALERT_THRESHOLD = int(os.getenv("NON_IP_ALERT_THRESHOLD", 1))
APPRISE_URLS = [url.strip() for url in os.getenv("APPRISE_URLS", None).split(",")]
ALERT_COOLDOWN_SECONDS = int(os.getenv("ALERT_COOLDOWN_SECONDS", 3600))

# --- Global State ---
# Stores tuples of (timestamp, src_mac, target_ip) for ARP
packet_log = deque(maxlen=1_000_000)  # Bound memory usage to prevent unbounded growth
packet_lock = threading.Lock()
arp_last_alert_time = 0

# Stores tuples of (timestamp, src_mac) for STP
stp_packet_log = deque(maxlen=1_000_000)  # Bound memory usage
stp_packet_lock = threading.Lock()
stp_last_alert_time = 0

# Stores tuples of (timestamp, src_mac) for other non-IP frames
non_ip_packet_log = deque(maxlen=1_000_000)  # Bound memory usage
non_ip_packet_lock = threading.Lock()
non_ip_last_alert_time = 0

# Stores tuples of (timestamp, src_mac) for IP broadcasts
ip_broadcast_packet_log = deque(maxlen=1_000_000)  # Bound memory usage
ip_broadcast_packet_lock = threading.Lock()
ip_broadcast_last_alert_time = 0

sniffer_thread = None
monitor_tasks = []


# --- Slack Alerter ---
def send_slack_alert(count: int, alert_type: str, window: int, threshold: int):
    """Sends a notification to a Slack channel via a webhook using Apprise."""
    if not APPRISE_URLS:
        logging.warning("APPRISE_URLS not set. Skipping alert.")
        return

    if alert_type == "ARP":
        title = f"⚠️ High ARP Broadcast Rate Detected on {IX_NAME}!"
        body = (
            f"{count} ARP requests detected in the last {window} seconds "
            f"(Threshold: {threshold})."
        )
    elif alert_type == "STP":
        title = f"⚠️ High Spanning Tree (STP) Frame Rate Detected on {IX_NAME}!"
        body = (
            f"{count} STP BPDUs detected in the last {window} seconds "
            f"(Threshold: {threshold})."
        )
    elif alert_type == "NON_IP":
        title = f"⚠️ High Non-IP Frame Rate Detected on {IX_NAME}!"
        body = (
            f"{count} other non-IP frames detected in the last {window} seconds "
            f"(Threshold: {threshold})."
        )
    elif alert_type == "IP_BROADCAST":
        title = f"⚠️ High IP Broadcast Rate Detected on {IX_NAME}!"
        body = (
            f"{count} IP broadcast packets detected in the last {window} seconds "
            f"(Threshold: {threshold})."
        )
    else:
        logging.error(f"Unknown alert type: {alert_type}")
        return

    try:
        apobj = apprise.Apprise()
        for url in APPRISE_URLS:
            apobj.add(url)

        success = apobj.notify(
            body=body,
            title=title,
            notify_type=NotifyType.WARNING,
        )

        if success:
            logging.info(f"Apprise alert for {alert_type} sent successfully.")
        else:
            logging.error(f"Failed to send Apprise alert for {alert_type}.")
    except Exception as e:
        logging.error(f"Failed to send Apprise alert for {alert_type}: {e}")


# --- Scapy Sniffer ---
def has_net_raw_capability():
    """Checks for CAP_NET_RAW capability, required for sniffing."""
    if hasattr(socket, "AF_PACKET"):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            s.close()
            return True
        except PermissionError:
            return False
    # Fallback for non-Linux systems.
    return os.geteuid() == 0


def packet_callback(packet):
    """Callback function for scapy's sniff(). Appends packet info to relevant deques."""
    if packet.haslayer(ARP) and packet[ARP].op == 1:  # ARP "who-has"
        with packet_lock:
            packet_log.append((time.time(), packet[ARP].hwsrc, packet[ARP].pdst))
    elif packet.haslayer(STP):
        with stp_packet_lock:
            # For STP frames, we just need the source MAC
            stp_packet_log.append((time.time(), packet.src))
    elif (
        packet.haslayer(IP)
        and packet[Ether].dst == "ff:ff:ff:ff:ff:ff"  # Use Ether layer for accurate dst MAC
        and not packet.haslayer(ARP)
    ):
        with ip_broadcast_packet_lock:
            ip_broadcast_packet_log.append((time.time(), packet.src))
    elif not packet.haslayer(ARP) and not packet.haslayer(STP):
        with non_ip_packet_lock:
            non_ip_packet_log.append((time.time(), packet.src))


def start_sniffer():
    """Starts the Scapy packet sniffer in a separate thread."""
    global sniffer_thread
    if not has_net_raw_capability():
        logging.error(
            "Scapy requires CAP_NET_RAW capability. "
            "Please run with sudo or grant the capability."
        )
        return

    # The filter below captures non-IP/IPv6 frames (like ARP, STP) AND IPv4 broadcast packets.
    logging.info(f"Starting packet sniffer on interfaces: {INTERFACES}")
    sniffer_thread = threading.Thread(
        target=lambda: sniff(
            iface=INTERFACES,
            prn=packet_callback,
            filter="(not (ip or ip6)) or (ip and ether host ff:ff:ff:ff:ff:ff)",
            store=0,
        ),
        daemon=True,
    )
    sniffer_thread.start()


# --- Background Monitoring Tasks ---
async def monitor_arp_packets():
    """Periodically checks ARP packet counts and triggers alerts."""
    global arp_last_alert_time
    while True:
        await asyncio.sleep(5)  # Check every 5 seconds
        now = time.time()

        with packet_lock:
            # Prune old packets
            while packet_log and packet_log[0][0] < now - TIME_WINDOW_SECONDS:
                packet_log.popleft()
            current_count = len(packet_log)

        if current_count > ARP_ALERT_THRESHOLD:
            if now - arp_last_alert_time > ALERT_COOLDOWN_SECONDS:
                logging.warning(f"ARP threshold exceeded: {current_count} packets.")
                await asyncio.to_thread(
                    send_slack_alert,
                    current_count,
                    "ARP",
                    TIME_WINDOW_SECONDS,
                    ARP_ALERT_THRESHOLD,
                )
                arp_last_alert_time = now
            else:
                logging.info(
                    f"ARP threshold exceeded but in cooldown. Count: {current_count}"
                )


async def monitor_stp_packets():
    """Periodically checks STP packet counts and triggers alerts."""
    global stp_last_alert_time
    while True:
        await asyncio.sleep(5)  # Check every 5 seconds
        now = time.time()

        with stp_packet_lock:
            # Prune old packets
            while stp_packet_log and stp_packet_log[0][0] < now - TIME_WINDOW_SECONDS:
                stp_packet_log.popleft()
            current_count = len(stp_packet_log)

        if current_count > STP_ALERT_THRESHOLD:
            if now - stp_last_alert_time > ALERT_COOLDOWN_SECONDS:
                logging.warning(f"STP threshold exceeded: {current_count} packets.")
                await asyncio.to_thread(
                    send_slack_alert,
                    current_count,
                    "STP",
                    TIME_WINDOW_SECONDS,
                    STP_ALERT_THRESHOLD,
                )
                stp_last_alert_time = now
            else:
                logging.info(
                    f"STP threshold exceeded but in cooldown. Count: {current_count}"
                )


async def monitor_non_ip_packets():
    """Periodically checks non-IP packet counts and triggers alerts."""
    global non_ip_last_alert_time
    while True:
        await asyncio.sleep(5)  # Check every 5 seconds
        now = time.time()

        with non_ip_packet_lock:
            # Prune old packets
            while (
                non_ip_packet_log
                and non_ip_packet_log[0][0] < now - TIME_WINDOW_SECONDS
            ):
                non_ip_packet_log.popleft()
            current_count = len(non_ip_packet_log)

        if current_count > NON_IP_ALERT_THRESHOLD:
            if now - non_ip_last_alert_time > ALERT_COOLDOWN_SECONDS:
                logging.warning(f"Non-IP threshold exceeded: {current_count} packets.")
                await asyncio.to_thread(
                    send_slack_alert,
                    current_count,
                    "NON_IP",
                    TIME_WINDOW_SECONDS,
                    NON_IP_ALERT_THRESHOLD,
                )
                non_ip_last_alert_time = now
            else:
                logging.info(
                    f"Non-IP threshold exceeded but in cooldown. Count: {current_count}"
                )


async def monitor_ip_broadcast_packets():
    """Periodically checks IP broadcast packet counts and triggers alerts."""
    global ip_broadcast_last_alert_time
    while True:
        await asyncio.sleep(5)  # Check every 5 seconds
        now = time.time()

        with ip_broadcast_packet_lock:
            # Prune old packets
            while (
                ip_broadcast_packet_log
                and ip_broadcast_packet_log[0][0] < now - TIME_WINDOW_SECONDS
            ):
                ip_broadcast_packet_log.popleft()
            current_count = len(ip_broadcast_packet_log)

        if current_count > IP_BROADCAST_ALERT_THRESHOLD:
            if now - ip_broadcast_last_alert_time > ALERT_COOLDOWN_SECONDS:
                logging.warning(
                    f"IP Broadcast threshold exceeded: {current_count} packets."
                )
                await asyncio.to_thread(
                    send_slack_alert,
                    current_count,
                    "IP_BROADCAST",
                    TIME_WINDOW_SECONDS,
                    IP_BROADCAST_ALERT_THRESHOLD,
                )
                ip_broadcast_last_alert_time = now
            else:
                logging.info(
                    f"IP Broadcast threshold exceeded but in cooldown. Count: {current_count}"
                )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initializes the sniffer and monitoring tasks on app startup."""
    global monitor_tasks
    start_sniffer()
    monitor_tasks = [
        asyncio.create_task(monitor_arp_packets()),
        asyncio.create_task(monitor_stp_packets()),
        asyncio.create_task(monitor_non_ip_packets()),
        asyncio.create_task(monitor_ip_broadcast_packets()),
    ]
    try:
        yield
    finally:
        for task in monitor_tasks:
            task.cancel()
        await asyncio.gather(*monitor_tasks, return_exceptions=True)
        if sniffer_thread:
            sniffer_thread.join(timeout=1)


# --- FastAPI Application ---
app = FastAPI(title="ARP Monitor", lifespan=lifespan)
templates = Jinja2Templates(directory="templates")


@app.get("/", response_class=HTMLResponse)
async def get_root(request: Request):
    """Serves the main HTML page."""
    return templates.TemplateResponse(
        "index.html", {"request": request, "ix_name": IX_NAME}
    )


@app.get("/health")
async def get_health():
    """Checks the health of the sniffer and monitoring tasks."""
    details = {}
    is_healthy = True

    # Check sniffer thread
    if sniffer_thread and sniffer_thread.is_alive():
        details["sniffer_thread"] = "running"
    else:
        details["sniffer_thread"] = "not running"
        is_healthy = False
        logging.error("Health check failed: Sniffer thread is not running.")

    # Check asyncio monitoring tasks
    if not monitor_tasks:
        details["monitor_tasks"] = "not initialized"
        is_healthy = False
        logging.error("Health check failed: monitor_tasks not initialized.")
    else:
        running_tasks = 0
        for task in monitor_tasks:
            if not task.done():
                running_tasks += 1
            else:
                try:
                    # This will raise the exception if one occurred
                    task.result()
                except asyncio.CancelledError:
                    pass  # Not a failure
                except Exception as e:
                    logging.error(f"A monitoring task has failed with exception: {e}")
        details["monitor_tasks_running"] = f"{running_tasks}/{len(monitor_tasks)}"
        if running_tasks < len(monitor_tasks):
            is_healthy = False
            logging.error(
                f"Health check failed: {len(monitor_tasks) - running_tasks} monitoring task(s) are not running."
            )

    if is_healthy:
        return JSONResponse(content={"status": "ok", "details": details})
    else:
        return JSONResponse(
            content={"status": "unhealthy", "details": details}, status_code=503
        )


@app.get("/api/data")
async def get_api_data():
    """Provides data for the frontend charts and tables."""
    now = time.time()
    bins = 60  # Fixed 60 bins for the charts

    # --- ARP Data Processing ---
    arp_bin_size = TIME_WINDOW_SECONDS / bins
    arp_labels = []
    arp_values = [0] * bins
    with packet_lock:
        current_arp_packets = list(packet_log)

    arp_source_macs = Counter()
    arp_target_ips = Counter()

    for ts, src_mac, target_ip in current_arp_packets:
        age = now - ts
        if age < TIME_WINDOW_SECONDS:
            bin_index = int(age // arp_bin_size)
            if 0 <= bin_index < bins:
                arp_values[bins - 1 - bin_index] += 1
            arp_source_macs[src_mac] += 1
            arp_target_ips[target_ip] += 1

    top_arp_sources = arp_source_macs.most_common(10)
    top_arp_destinations = arp_target_ips.most_common(10)

    for i in range(bins):
        dt = datetime.fromtimestamp(now - (bins - 1 - i) * arp_bin_size)
        arp_labels.append(dt.strftime("%H:%M:%S"))

    # --- STP Data Processing ---
    stp_bin_size = TIME_WINDOW_SECONDS / bins
    stp_labels = []
    stp_values = [0] * bins
    with stp_packet_lock:
        current_stp_packets = list(stp_packet_log)

    stp_source_macs = Counter()
    for ts, src_mac in current_stp_packets:
        age = now - ts
        if age < TIME_WINDOW_SECONDS:
            bin_index = int(age // stp_bin_size)
            if 0 <= bin_index < bins:
                stp_values[bins - 1 - bin_index] += 1
            stp_source_macs[src_mac] += 1

    top_stp_sources = stp_source_macs.most_common(10)

    for i in range(bins):
        dt = datetime.fromtimestamp(now - (bins - 1 - i) * stp_bin_size)
        stp_labels.append(dt.strftime("%H:%M:%S"))

    # --- Non-IP Data Processing ---
    non_ip_bin_size = TIME_WINDOW_SECONDS / bins
    non_ip_labels = []
    non_ip_values = [0] * bins
    with non_ip_packet_lock:
        current_non_ip_packets = list(non_ip_packet_log)

    non_ip_source_macs = Counter()
    for ts, src_mac in current_non_ip_packets:
        age = now - ts
        if age < TIME_WINDOW_SECONDS:
            bin_index = int(age // non_ip_bin_size)
            if 0 <= bin_index < bins:
                non_ip_values[bins - 1 - bin_index] += 1
            non_ip_source_macs[src_mac] += 1

    top_non_ip_sources = non_ip_source_macs.most_common(10)

    for i in range(bins):
        dt = datetime.fromtimestamp(now - (bins - 1 - i) * non_ip_bin_size)
        non_ip_labels.append(dt.strftime("%H:%M:%S"))

    # --- IP Broadcast Data Processing ---
    ip_broadcast_bin_size = TIME_WINDOW_SECONDS / bins
    ip_broadcast_labels = []
    ip_broadcast_values = [0] * bins
    with ip_broadcast_packet_lock:
        current_ip_broadcast_packets = list(ip_broadcast_packet_log)

    ip_broadcast_source_macs = Counter()
    for ts, src_mac in current_ip_broadcast_packets:
        age = now - ts
        if age < TIME_WINDOW_SECONDS:
            bin_index = int(age // ip_broadcast_bin_size)
            if 0 <= bin_index < bins:
                ip_broadcast_values[bins - 1 - bin_index] += 1
            ip_broadcast_source_macs[src_mac] += 1

    top_ip_broadcast_sources = ip_broadcast_source_macs.most_common(10)

    for i in range(bins):
        dt = datetime.fromtimestamp(now - (bins - 1 - i) * ip_broadcast_bin_size)
        ip_broadcast_labels.append(dt.strftime("%H:%M:%S"))

    return JSONResponse(
        content={
            "interfaces": INTERFACES,
            "arp_data": {
                "labels": arp_labels,
                "values": arp_values,
                "threshold": ARP_ALERT_THRESHOLD,
                "window_seconds": TIME_WINDOW_SECONDS,
                "top_sources": top_arp_sources,
                "top_destinations": top_arp_destinations,
            },
            "stp_data": {
                "labels": stp_labels,
                "values": stp_values,
                "threshold": STP_ALERT_THRESHOLD,
                "window_seconds": TIME_WINDOW_SECONDS,
                "top_sources": top_stp_sources,
            },
            "non_ip_data": {
                "labels": non_ip_labels,
                "values": non_ip_values,
                "threshold": NON_IP_ALERT_THRESHOLD,
                "window_seconds": TIME_WINDOW_SECONDS,
                "top_sources": top_non_ip_sources,
            },
            "ip_broadcast_data": {
                "labels": ip_broadcast_labels,
                "values": ip_broadcast_values,
                "threshold": IP_BROADCAST_ALERT_THRESHOLD,
                "window_seconds": TIME_WINDOW_SECONDS,
                "top_sources": top_ip_broadcast_sources,
            },
        }
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
