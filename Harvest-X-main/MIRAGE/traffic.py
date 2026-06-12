import subprocess
import threading
import logging
import platform

logger = logging.getLogger("TrafficMonitor")

class TrafficMonitor:
    """
    Traffic Monitor using tcpdump.
    Analyzes live traffic on the host or container network.
    """
    
    def __init__(self, interface="any", pcap_file="traffic.pcap"):
        self.interface = interface
        self.pcap_file = pcap_file
        self.process = None
        
    def start(self):
        if platform.system() == "Windows":
            logger.warning("tcpdump is not natively supported on Windows. Skipping traffic monitor.")
            return
            
        cmd = ["tcpdump", "-i", self.interface, "-w", self.pcap_file]
        try:
            self.process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logger.info(f"Started tcpdump on interface {self.interface}, saving to {self.pcap_file}")
        except FileNotFoundError:
            logger.error("tcpdump not found. Please install it.")
            
    def stop(self):
        if self.process:
            self.process.terminate()
            self.process.wait()
            logger.info("Stopped tcpdump")
