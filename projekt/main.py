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

WINDOW_SIZE = 10
STEP_SIZE = 2

logger.info("System started. Beginning data collection (sliding window mode)...")

buffer = []
last_aggregation = time.time()

try:
    while True:
        try:
            new_packets = capture_packets(duration=1)
            now = time.time()

            for packet in new_packets:
                packet["timestamp"] = now
                buffer.append(packet)

            buffer = [p for p in buffer if now - p["timestamp"] <= WINDOW_SIZE]

            if now - last_aggregation >= STEP_SIZE:
                logger.info(f"Aggregating window: {len(buffer)} packets in last {WINDOW_SIZE}s")
                aggregate_and_save(buffer)
                last_aggregation = now

        except Exception as e:
            logger.error(f"Unexpected error in main loop: {e}")

except KeyboardInterrupt:
    logger.info("System stopped by user.")
    print("\nSystem stopped.")