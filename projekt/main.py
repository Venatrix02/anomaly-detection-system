import time
import logging
import signal
import sys
from collector.sniffer import capture_packets, stop_sniffer
from collector.window_manager import SlidingWindow
from features.aggregator import aggregate_packets
from database.repository import save_metric, save_anomaly, save_alert, determine_severity
from detector import AnomalyDetector

#ustawienia logowania

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

window = SlidingWindow(window_size=WINDOW_SIZE)
last_aggregation = time.time()

#funkcja obsługi sygnałów (Ctrl+C, kill)

def signal_handler(sig, frame):
    logger.info("\n[!] Otrzymano sygnal zamkniecia. Zatrzymywanie systemu...")
    stop_sniffer()
    sys.exit(0)

#rejestracja handlerów sygnałów

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

#wczytanie modelu

logger.info("Loading anomaly detection model...")

detector = None
model_loaded = False

try:
    detector = AnomalyDetector()
    model_loaded = detector.model is not None
    if model_loaded:
        logger.info("Model loaded: " + detector.algorithm_type)
    else:
        logger.warning("No model available. System will ONLY collect data (no anomaly detection).")
except Exception as e:
    logger.warning("Could not load model: " + str(e) + ". System will ONLY collect data.")
    detector = None
    model_loaded = False

logger.info("System started. Beginning data collection...")

try:
    while True:
        new_packets = capture_packets(duration=1)
        now = time.time()

        window.add_packets(new_packets, now)

        if now - last_aggregation >= STEP_SIZE:
            packets_in_window = window.get_packets()
            logger.info(
                "Aggregating " + str(len(packets_in_window)) + " packets from last " + str(WINDOW_SIZE) + " seconds"
            )
            metric_data = aggregate_packets(packets_in_window)
            if metric_data:
                metric_id = save_metric(metric_data)

                if model_loaded and detector is not None:
                    is_anomaly, score, model_id = detector.predict(metric_data)
                    if is_anomaly:
                        logger.warning("ANOMALY DETECTED! Score: " + str(round(score, 4)))
                        severity = determine_severity(score)
                        anomaly_data = {
                            'anomaly_score': score,
                            'severity_level': severity,
                            'description': "Anomaly detected by " + detector.algorithm_type,
                            'metric_id': metric_id,
                            'model_id': model_id
                        }
                        anomaly_id = save_anomaly(anomaly_data)
                        if anomaly_id:
                            save_alert(anomaly_id, severity)

            last_aggregation = now

except KeyboardInterrupt:
    logger.info("System stopped by user.")
    stop_sniffer()
    print("\nSystem stopped.")
except Exception as e:
    logger.error("Unexpected error in main loop: " + str(e))
    stop_sniffer()