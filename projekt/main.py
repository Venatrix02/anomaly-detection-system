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
logger.info("System uruchomiony. Rozpoczęcie zbierania danych...")

while True:
    try:
        logger.info("Rozpoczynanie nowego cykl zbierania pakietów...")
        packets = capture_packets(duration=10)
        aggregate_and_save(packets)
    except Exception as e:
        logger.error(f"Nieoczekiwany błąd w pętli głównej: {e}")
    time.sleep(1)