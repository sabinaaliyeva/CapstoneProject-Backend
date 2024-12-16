#!/usr/bin/env python3

import subprocess
import scapy.all as scapy
import time
import threading
import logging
import os
import sys
from scapy.layers.dot11 import Dot11Deauth, Dot11, Dot11Beacon, Dot11ProbeResp

# -------------------- Configuration -------------------- #

# Deauthentication Attack Detection Parameters
DEAUTH_THRESHOLD = 120        # Number of deauth frames from the same source before alert
DEAUTH_TIME_WINDOW = 120      # Time window in seconds to track deauth frames

# Evil Twin Detection Parameters
EVIL_TWIN_SIGNAL_DIFF = 5          # Maximum allowed difference in signal strength (dBm)
EVIL_TWIN_ENCRYPTION_DIFF = True   # Whether to consider encryption type differences

# Path to NetworkManager unmanaged configuration
UNMANAGED_CONF_PATH = "/etc/NetworkManager/conf.d/unmanaged.conf"

# -------------------- Logging Configuration -------------------- #

# Configure logging to output to console only
logging.basicConfig(
    level=logging.INFO,  # Change to DEBUG for more detailed logs
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

# -------------------- Helper Functions -------------------- #

def freq_to_channel(freq):
    """Convert frequency to channel number."""
    if 2412 <= freq <= 2472:
        return (freq - 2412) // 5 + 1
    elif freq == 2484:
        return 14
    elif 5180 <= freq <= 5825:
        return (freq - 5000) // 5
    else:
        return "Unknown"

def check_root():
    """Ensure the script is run as root."""
    if os.geteuid() != 0:
        logging.error("This script must be run as root. Please run with sudo.")
        sys.exit(1)

def install_iw():
    """Check if 'iw' is installed, install if not."""
    try:
        subprocess.check_call("which iw", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        logging.info("'iw' not found. Installing 'iw'...")
        try:
            subprocess.check_call("apt update && apt install -y iw", shell=True)
            logging.info("'iw' installed successfully.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to install 'iw': {e}")
            sys.exit(1)

def prevent_networkmanager_from_managing(adapters):
    """Automatically configure NetworkManager to ignore specified wireless adapters."""
    try:
        # Prepare unmanaged devices string
        unmanaged_devices = ""
        for adapter in adapters:
            unmanaged_devices += f"interface-name:{adapter.name};"
        unmanaged_devices = unmanaged_devices.rstrip(';')  # Remove trailing semicolon

        # Write to unmanaged.conf
        with open(UNMANAGED_CONF_PATH, 'w') as f:
            f.write("[keyfile]\n")
            f.write(f"unmanaged-devices={unmanaged_devices}\n")

        logging.info("Configured NetworkManager to ignore specified wireless adapters.")

        # Restart NetworkManager
        subprocess.check_call("systemctl restart NetworkManager", shell=True)
        logging.info("NetworkManager restarted successfully.")

    except Exception as e:
        logging.error(f"Failed to configure NetworkManager: {e}")
        sys.exit(1)

def find_network_adapters():
    """Find all wireless network adapters using 'iw dev'."""
    adapters = []
    try:
        # Use iw dev to find all wireless adapters
        output = subprocess.check_output("iw dev", shell=True).decode("utf-8")
        adapter_names = []
        for line in output.splitlines():
            if line.strip().startswith("Interface"):
                adapter_name = line.strip().split()[1]
                adapter_names.append(adapter_name)
        for name in adapter_names:
            adapters.append(NetworkAdapter(name))
    except subprocess.CalledProcessError as e:
        logging.error(f"Error finding network adapters: {e}")
    return adapters

def get_available_channels():
    """Return a list of available channels for 2.4 GHz."""
    return list(range(1, 12))  # Channels 1 to 11

def assign_channels(adapters, channels):
    """Assign channels to adapters in a round-robin fashion."""
    assigned = {}
    num_channels = len(channels)
    for i, adapter in enumerate(adapters):
        channel = channels[i % num_channels]  # Assign channels in a round-robin fashion
        assigned[adapter] = channel
    return assigned

def get_connected_network():
    """Retrieve the connected WiFi's SSID, BSSID, channel, and interface using iw."""
    try:
        # List all wireless interfaces
        interfaces = subprocess.check_output("iw dev | grep Interface | awk '{print $2}'", shell=True).decode("utf-8").strip().split('\n')
        for iface in interfaces:
            try:
                output = subprocess.check_output(f"iw dev {iface} link", shell=True).decode("utf-8")
                if "Not connected." in output:
                    continue
                # Parse SSID
                ssid_line = next((line for line in output.splitlines() if "SSID:" in line), None)
                ssid = ssid_line.split("SSID:")[1].strip() if ssid_line else "Unknown"
                # Parse BSSID
                bssid_line = next((line for line in output.splitlines() if "Connected to" in line), None)
                bssid = bssid_line.split("Connected to")[1].strip().split(' ')[0] if bssid_line else "Unknown"
                # Parse Channel
                freq_line = next((line for line in output.splitlines() if "freq:" in line), None)
                if freq_line:
                    freq_str = freq_line.split("freq:")[1].strip()
                    try:
                        freq = int(float(freq_str))  # Convert '5240.0' to 5240
                    except ValueError:
                        logging.error(f"Invalid frequency format: {freq_str}")
                        freq = None
                else:
                    freq = None
                channel = freq_to_channel(freq) if freq else "Unknown"
                return ssid, bssid, channel, iface
            except subprocess.CalledProcessError:
                continue
    except Exception as e:
        logging.error(f"Failed to retrieve connected network information using iw: {e}")
    return None, None, None, None

def get_ap_details(ssid, bssid, interface):
    """Retrieve signal strength and encryption type for the connected AP."""
    try:
        output = subprocess.check_output(f"iw dev {interface} scan ap {bssid}", shell=True).decode("utf-8")
        signal_strength = None
        encryption = "Open"
        for line in output.splitlines():
            if "signal:" in line:
                # Example line: " signal: -40.00 dBm"
                parts = line.strip().split()
                if len(parts) >= 2:
                    try:
                        signal_strength = int(float(parts[1]))
                    except ValueError:
                        logging.error(f"Invalid signal strength format: {parts[1]}")
                        signal_strength = None
            if "RSN:" in line:
                encryption = "WPA2"
            elif "WPA:" in line:
                encryption = "WPA"
        return signal_strength, encryption
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to retrieve AP details for {bssid} on {interface}: {e}")
        return None, "Unknown"

def listen_for_exit(scanner_threads, adapters):
    """Listen for 'Q' keypress to gracefully exit the script."""
    try:
        while True:
            user_input = input().strip().lower()
            if user_input == 'q':
                logging.info("Exit command received. Stopping all scanners and reverting adapters...")
                for scanner in scanner_threads:
                    scanner.stop()
                for scanner in scanner_threads:
                    scanner.join()
                # Revert all adapters to managed mode
                for adapter in adapters:
                    adapter.set_managed_mode()
                # Remove unmanaged.conf
                if os.path.exists(UNMANAGED_CONF_PATH):
                    subprocess.check_call(f"rm -rf {UNMANAGED_CONF_PATH}", shell=True)
                    logging.info(f"Removed {UNMANAGED_CONF_PATH}.")
                # Restart NetworkManager
                subprocess.check_call("systemctl restart NetworkManager", shell=True)
                logging.info("All adapters reverted to managed mode and NetworkManager restarted.")
                sys.exit(0)
    except KeyboardInterrupt:
        logging.info("KeyboardInterrupt detected. Exiting...")
        for scanner in scanner_threads:
            scanner.stop()
        for scanner in scanner_threads:
            scanner.join()
        # Revert all adapters to managed mode
        for adapter in adapters:
            adapter.set_managed_mode()
        # Remove unmanaged.conf
        if os.path.exists(UNMANAGED_CONF_PATH):
            subprocess.check_call(f"rm -rf {UNMANAGED_CONF_PATH}", shell=True)
            logging.info(f"Removed {UNMANAGED_CONF_PATH}.")
        # Restart NetworkManager
        subprocess.check_call("systemctl restart NetworkManager", shell=True)
        logging.info("All adapters reverted to managed mode and NetworkManager restarted.")
        sys.exit(0)

# -------------------- Classes -------------------- #

class NetworkAdapter:
    def __init__(self, name):
        self.name = name
        self.current_channel = None

    def set_monitor_mode(self):
        try:
            logging.info(f"Setting {self.name} to monitor mode...")
            subprocess.check_call(f"ip link set dev {self.name} down", shell=True)
            subprocess.check_call(f"iw dev {self.name} set type monitor", shell=True)
            subprocess.check_call(f"ip link set dev {self.name} up", shell=True)
            logging.info(f"{self.name} set to monitor mode successfully.")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to set monitor mode on {self.name}: {e}")
            return False

    def set_managed_mode(self):
        try:
            logging.info(f"Setting {self.name} back to managed mode...")
            subprocess.check_call(f"ip link set dev {self.name} down", shell=True)
            subprocess.check_call(f"iw dev {self.name} set type managed", shell=True)
            subprocess.check_call(f"ip link set dev {self.name} up", shell=True)
            logging.info(f"{self.name} set to managed mode successfully.")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to set managed mode on {self.name}: {e}")
            return False

    def set_channel(self, channel):
        try:
            subprocess.check_call(f"iw dev {self.name} set channel {channel}", shell=True)
            self.current_channel = channel
            logging.info(f"Set {self.name} to channel {channel}")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to set channel {channel} on {self.name}: {e}")
            return False

class DeauthMonitor:
    def __init__(self, threshold=DEAUTH_THRESHOLD, time_window=DEAUTH_TIME_WINDOW):
        self.deauth_table = {}
        self.threshold = threshold
        self.time_window = time_window
        self.lock = threading.Lock()

    def process_deauth_packet(self, packet):
        if not packet.haslayer(Dot11Deauth):
            return

        source_mac = packet[Dot11].addr2.lower()
        destination_mac = packet[Dot11].addr1.lower()
        current_time = time.time()

        with self.lock:
            if source_mac in self.deauth_table:
                record = self.deauth_table[source_mac]
                record['count'] += 1
                record['last_seen'] = current_time
                logging.debug(f"Deauth record updated: {source_mac}, count: {record['count']}")
                if record['count'] >= self.threshold:
                    logging.warning(f"Deauthentication Attack Detected! Source MAC: {source_mac}, Destination MAC: {destination_mac}")
                    # Once alerted, remove the record to prevent multiple alerts
                    del self.deauth_table[source_mac]
            else:
                self.deauth_table[source_mac] = {'count': 1, 'last_seen': current_time}
                logging.debug(f"New Deauth record: {source_mac}, count: 1")

        # Clean up old entries
        self.cleanup(current_time)

    def cleanup(self, current_time):
        with self.lock:
            to_delete = []
            for mac, record in self.deauth_table.items():
                if current_time - record['last_seen'] > self.time_window:
                    to_delete.append(mac)
            for mac in to_delete:
                del self.deauth_table[mac]
                logging.debug(f"Deauth record for MAC {mac} expired and removed.")

class EvilTwinMonitor:
    def __init__(self, target_ssid, connected_bssid, signal_diff=EVIL_TWIN_SIGNAL_DIFF, encryption_diff=EVIL_TWIN_ENCRYPTION_DIFF):
        self.target_ssid = target_ssid
        self.connected_bssid = connected_bssid.lower()
        self.signal_diff = signal_diff
        self.encryption_diff = encryption_diff
        self.ap_table = {}
        self.lock = threading.Lock()
        self.evil_twin_candidates = {}  # Tracks APs that meet Evil Twin criteria

    def process_beacon_packet(self, packet):
        if packet.haslayer(Dot11):
            ssid = packet[Dot11].info.decode('utf-8', errors='ignore') if packet[Dot11].info else "<Hidden SSID>"
            if ssid.lower() != self.target_ssid.lower():
                return

            source_mac = packet[Dot11].addr2.lower()  # Sender
            bssid = packet[Dot11].addr1.lower()        # Receiver (usually same as BSSID)
            signal_strength = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else None
            encryption = self.get_encryption(packet)

            if not signal_strength:
                return  # Unable to determine signal strength

            # Ignore if the BSSID matches the connected AP's BSSID
            if self.connected_bssid and bssid == self.connected_bssid:
                logging.debug(f"Detected beacon from connected AP {bssid}. Ignoring.")
                return

            with self.lock:
                if ssid in self.ap_table:
                    existing_bssid, existing_signal, existing_encryption = self.ap_table[ssid]
                    if source_mac != existing_bssid:
                        signal_diff_value = abs(signal_strength - existing_signal)
                        encryption_diff_flag = (existing_encryption != encryption) if self.encryption_diff else False

                        if signal_diff_value <= self.signal_diff or encryption_diff_flag:
                            # Potential Evil Twin
                            if source_mac not in self.evil_twin_candidates:
                                self.evil_twin_candidates[source_mac] = {'ssid': ssid, 'bssid': source_mac}
                                logging.warning(
                                    f"Possible Evil Twin AP Detected! Rogue AP {source_mac} broadcasting SSID '{ssid}' "
                                    f"with signal strength difference of {signal_diff_value} dBm "
                                    f"{'and different encryption' if encryption_diff_flag else ''}."
                                )
                else:
                    self.ap_table[ssid] = (bssid, signal_strength, encryption)
                    logging.debug(f"Added AP to tracking: SSID '{ssid}', BSSID {bssid}, Signal {signal_strength} dBm, Encryption {encryption}")

    def get_encryption(self, packet):
        """Extract encryption type from beacon or probe response packet."""
        encryption = "Open"
        if packet.haslayer(scapy.Dot11Elt):
            elems = packet[scapy.Dot11Elt]
            while isinstance(elems, scapy.Dot11Elt):
                if elems.ID == 48:
                    encryption = "WPA2"
                    break
                elif elems.ID == 221 and elems.info.startswith(b'\x00P\xf2\x01\x01\x00'):
                    encryption = "WPA"
                    break
                elems = elems.payload
        return encryption

    def check_evil_twin_with_deauth(self, deauth_monitor):
        """Check if any Evil Twin candidates are actively sending Deauth frames."""
        with deauth_monitor.lock, self.lock:
            for mac in list(self.evil_twin_candidates.keys()):
                if mac in deauth_monitor.deauth_table and deauth_monitor.deauth_table[mac]['count'] >= DEAUTH_THRESHOLD:
                    logging.warning(f"Evil Twin Attack Confirmed! Rogue AP {mac} is actively sending Deauthentication frames.")
                    # Once confirmed, remove from candidates to prevent multiple alerts
                    del self.evil_twin_candidates[mac]

    def cleanup(self, current_time):
        with self.lock:
            to_delete = []
            for mac, info in self.evil_twin_candidates.items():
                # Implement any necessary cleanup, e.g., if AP is no longer detected
                pass
            for mac in to_delete:
                del self.evil_twin_candidates[mac]
                logging.debug(f"Evil Twin candidate {mac} expired and removed.")

class AttackDetector:
    def __init__(self, target_ssid, connected_bssid):
        self.target_ssid = target_ssid
        self.connected_bssid = connected_bssid
        self.deauth_monitor = DeauthMonitor()
        self.evil_twin_monitor = EvilTwinMonitor(target_ssid, connected_bssid)

    def process_packet(self, packet):
        try:
            # Deauthentication Attack Detection
            if packet.haslayer(Dot11Deauth):
                self.deauth_monitor.process_deauth_packet(packet)

            # Evil Twin Attack Detection (Rogue AP detection)
            if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
                self.evil_twin_monitor.process_beacon_packet(packet)

            # Check for Evil Twin confirmations
            self.evil_twin_monitor.check_evil_twin_with_deauth(self.deauth_monitor)

        except Exception as e:
            logging.error(f"Error processing packet: {e}")

class NetworkScanner(threading.Thread):
    def __init__(self, adapter, channel, detector, scan_type='Deauth'):
        super().__init__()
        self.adapter = adapter
        self.channel = channel
        self.detector = detector
        self.scan_type = scan_type  # 'Deauth' or 'Evil Twin'
        self.stop_sniffing = threading.Event()

    def run(self):
        # Set Monitor Mode
        if not self.adapter.set_monitor_mode():
            logging.error(f"Skipping scanning on {self.adapter.name} due to monitor mode failure.")
            return

        # Set Channel
        if self.channel:
            if not self.adapter.set_channel(self.channel):
                logging.error(f"Skipping scanning on {self.adapter.name} due to channel setting failure.")
                return

        logging.info(f"Started {self.scan_type} scanner on {self.adapter.name} at channel {self.channel}")

        try:
            scapy.sniff(
                iface=self.adapter.name,
                prn=self.detector.process_packet,
                store=False,
                stop_filter=lambda x: self.stop_sniffing.is_set()
            )
        except Exception as e:
            logging.error(f"Error while sniffing on {self.adapter.name}: {e}")

    def stop(self):
        self.stop_sniffing.set()

# -------------------- Main Function -------------------- #

def main():
    check_root()
    install_iw()

    # Retrieve connected network's SSID, BSSID, channel, and interface
    ssid, bssid, channel, connected_interface = get_connected_network()
    if not ssid or not bssid or channel == "Unknown" or not connected_interface:
        logging.error("Unable to retrieve connected network information. Exiting.")
        sys.exit(1)

    logging.info(f"Connected to SSID: {ssid}, BSSID: {bssid}, Channel: {channel}, Interface: {connected_interface}")

    # Find all network adapters
    adapters = find_network_adapters()

    if not adapters:
        logging.error("No wireless network adapters found.")
        sys.exit(1)

    logging.info(f"Found {len(adapters)} wireless network adapters: {[adapter.name for adapter in adapters]}")

    # Automatically use the last adapter for Evil Twin scanning
    evil_twin_adapter = adapters[-1]  # Assuming the last adapter is external
    logging.info(f"Selected {evil_twin_adapter.name} as the Evil Twin scanning adapter.")

    # Assign channels to other adapters (excluding the Evil Twin adapter)
    monitoring_adapters = adapters[:-1] if len(adapters) > 1 else []
    channels = get_available_channels()
    channel_assignment = assign_channels(monitoring_adapters, channels)

    # Prevent NetworkManager from managing these adapters
    prevent_networkmanager_from_managing(adapters)

    # Initialize AttackDetector with connected SSID and BSSID
    detector = AttackDetector(target_ssid=ssid, connected_bssid=bssid)

    # Pre-populate EvilTwinMonitor's ap_table with connected AP's details to avoid false positives
    signal_strength, encryption = get_ap_details(ssid, bssid, connected_interface)
    if signal_strength is not None and encryption != "Unknown":
        detector.evil_twin_monitor.ap_table[ssid] = (bssid.lower(), signal_strength, encryption)
        logging.debug(f"Pre-populated ap_table with connected AP: SSID '{ssid}', BSSID {bssid}, Signal {signal_strength} dBm, Encryption {encryption}")
    else:
        logging.warning("Could not retrieve connected AP's signal strength and encryption. Proceeding without pre-populating ap_table.")

    scanners = []

    # Start scanner for Evil Twin detection on the designated adapter
    # Set Evil Twin adapter to the connected channel only for listening
    if evil_twin_adapter.set_monitor_mode():
        if evil_twin_adapter.set_channel(channel):
            evil_twin_scanner = NetworkScanner(evil_twin_adapter, channel, detector, scan_type='Evil Twin')
            scanners.append(evil_twin_scanner)
            evil_twin_scanner.start()
            logging.info(f"Started Evil Twin scanner on {evil_twin_adapter.name} at channel {channel}")
        else:
            logging.error(f"Failed to set channel {channel} on {evil_twin_adapter.name}.")
    else:
        logging.error(f"Failed to set monitor mode on {evil_twin_adapter.name}.")

    # Start scanners for other adapters (if any) for Deauth detection
    for adapter in monitoring_adapters:
        assigned_channel = channel_assignment.get(adapter, None)
        if assigned_channel:
            scanner = NetworkScanner(adapter, assigned_channel, detector, scan_type='Deauth')
            scanners.append(scanner)
            scanner.start()
            logging.info(f"Started Deauth scanner on {adapter.name} at channel {assigned_channel}")
            time.sleep(1)  # Slight delay to avoid race conditions

    # Start a thread to listen for 'Q' keypress to exit
    exit_listener = threading.Thread(target=listen_for_exit, args=(scanners, adapters), daemon=True)
    exit_listener.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("KeyboardInterrupt detected. Stopping all scanners and reverting adapters...")
        for scanner in scanners:
            scanner.stop()
        for scanner in scanners:
            scanner.join()
        # Revert all adapters to managed mode
        for adapter in adapters:
            adapter.set_managed_mode()
        # Remove unmanaged.conf
        if os.path.exists(UNMANAGED_CONF_PATH):
            subprocess.check_call(f"rm -rf {UNMANAGED_CONF_PATH}", shell=True)
            logging.info(f"Removed {UNMANAGED_CONF_PATH}.")
        # Restart NetworkManager
        subprocess.check_call("systemctl restart NetworkManager", shell=True)
        logging.info("All adapters reverted to managed mode and NetworkManager restarted.")
        sys.exit(0)

if __name__ == "__main__":
    main()
