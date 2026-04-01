import time
import logging
from collector.sniffer import capture_packets
from collector.aggregator import aggregate_and_save

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("system.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)
logger.info("System started. Beginning data collection...")

try:
    while True:
        try:
            logger.info("Starting new packet capture cycle...")
            packets = capture_packets(duration=10)
            aggregate_and_save(packets)
        except Exception as e:
            logger.error(f"Unexpected error in main loop: {e}")
        time.sleep(1)
except KeyboardInterrupt:
    logger.info("System stopped by user.")
    print("\nSystem stopped.")