import time
import logging

from collector.sniffer import capture_packets
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

WINDOW_SIZE = 10 #ile sekund ruchu sieciowego ma być brane pod uwagę przy tworzeniu podsumowania
STEP_SIZE = 2 #co ile sekund jest robione podsumowanie i zapisywane do bazy

window = SlidingWindow(window_size=WINDOW_SIZE)
last_aggregation = time.time()

#wczytanie modelu wykrywającego anomalie

logger.info("Loading anomaly detection model...")
detector = AnomalyDetector()

logger.info("System started. Beginning data collection...")

try:

    #zbieranie nowych pakietów z ostatniej sekundy

    while True:
        new_packets = capture_packets(duration=1)
        now = time.time()

        #dodawanie nowych pakietów do okna czasowego i usuwanie starych

        window.add_packets(new_packets, now)

        #po minimalnym czasie określonym w STEP_SIZE, tworzenie podsumowania z pakietów w oknie czasowym i zapisywanie go

        if now - last_aggregation >= STEP_SIZE:
            packets_in_window = window.get_packets()
            logger.info(
                f"Aggregating {len(packets_in_window)} packets from last {WINDOW_SIZE} seconds"
            )
            metric_data = aggregate_packets(packets_in_window)
            
            if metric_data:

                #zapisanie metryki do bazy

                save_metric(metric_data)
                
                #wykrywanie anomalii

                is_anomaly, score, model_id = detector.predict(metric_data)
                
                if is_anomaly:
                    logger.warning(f"🚨 ANOMALY DETECTED! Score: {score:.4f}")
                    
                    #wyznaczanie poziomu istotności

                    severity = determine_severity(score)
                    
                    #przygotowanie danych anomalii do zapisu

                    anomaly_data = {
                        'anomaly_score': score,
                        'severity_level': severity,
                        'description': f"Anomaly detected by {detector.algorithm_type}",
                        'metric_id': None,  #tutaj trzeba by pobrać ID ostatnio zapisanej metryki
                        'model_id': model_id
                    }
                    
                    #zapisanie anomalii do bazy

                    anomaly_id = save_anomaly(anomaly_data)
                    
                    #zapisanie alertu do bazy

                    if anomaly_id:
                        save_alert(anomaly_id)
                
            last_aggregation = now

#użytkownik sam zatrzymał program (Ctrl+C)

except KeyboardInterrupt:
    logger.info("System stopped by user.")
    print("\nSystem stopped.")

#zapisywanie błędów do logu w przypadku nieoczekiwanych wyjątków

except Exception as e:
    logger.error(f"Unexpected error in main loop: {e}")