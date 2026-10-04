import joblib
import logging
import pandas as pd
from database.connection import SessionLocal
from database.tables import ModelInfo

logger = logging.getLogger(__name__)

#cechy używane do wykrywania anomalii (identyczna kolejność jak w train_model.py)

FEATURE_COLUMNS = [
    'packets_count',
    'unique_ips',
    'unique_ports',
    'avg_packet_size',
    'tcp_ratio',
    'udp_ratio',
    'other_ratio',
    'unique_connections',
    'dominant_port',
    'synchronization_packets_count',
    'acknowledgment_packets_count',
    'reset_packets_count',
    'finish_packets_count',
    'packet_size_std',
    'syn_to_ack_ratio'
]

#wykrywanie anomalii w czasie rzeczywistym

class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.threshold_stats = None
        self.algorithm_type = None
        self.model_id = None
        self._load_active_model()

    #wczytywanie aktywnego modelu z bazy danych i pliku .pkl

    def _load_active_model(self):
        with SessionLocal() as session:
            try:
                active_model_info = session.query(ModelInfo).filter(ModelInfo.is_active == True).first()
                if not active_model_info:
                    logger.warning("Brak aktywnego modelu w bazie. Używam domyślnego: Isolation Forest.")
                    self.algorithm_type = "IsolationForest"
                    self.model_id = 1
                else:
                    self.algorithm_type = active_model_info.algorithm_type
                    self.model_id = active_model_info.id
                logger.info("Ładowanie modelu: " + self.algorithm_type + " (ID: " + str(self.model_id) + ")")

                if self.algorithm_type == "IsolationForest":
                    self.model = joblib.load("models/isolation_forest.pkl")
                elif self.algorithm_type == "OneClassSVM":
                    loaded_data = joblib.load("models/one_class_svm.pkl")
                    self.model = loaded_data['model']
                    self.scaler = loaded_data['scaler']
                elif self.algorithm_type == "Threshold":
                    self.threshold_stats = joblib.load("models/threshold_method.pkl")
                else:
                    logger.error("Nieznany typ algorytmu: " + self.algorithm_type)
            except Exception as e:
                logger.error("Błąd podczas ładowania modelu: " + str(e))

    #sprawdzanie, czy podane cechy są anomalią

    def predict(self, metric_data):

        #przygotowanie DataFrame z nazwami kolumn

        X = pd.DataFrame([metric_data], columns=FEATURE_COLUMNS)

        if self.algorithm_type == "IsolationForest":
            prediction = self.model.predict(X)[0]
            score = self.model.score_samples(X)[0]
            is_anomaly = (prediction == -1)
        elif self.algorithm_type == "OneClassSVM":
            X_scaled = self.scaler.transform(X)
            prediction = self.model.predict(X_scaled)[0]
            score = self.model.decision_function(X_scaled)[0]
            is_anomaly = (prediction == -1)
        elif self.algorithm_type == "Threshold":
            is_anomaly = False
            max_deviation = 0
            means = self.threshold_stats['means']
            stds = self.threshold_stats['stds']
            n_sigmas = self.threshold_stats['n_sigmas']
            for i, col in enumerate(FEATURE_COLUMNS):
                val = X.iloc[0][i]
                mean = means.iloc[i] if hasattr(means, 'iloc') else means[i]
                std = stds.iloc[i] if hasattr(stds, 'iloc') else stds[i]
                deviation = abs(val - mean) / std if std > 0 else 0
                if deviation > max_deviation:
                    max_deviation = deviation
                if deviation > n_sigmas:
                    is_anomaly = True
            score = -max_deviation
        else:
            is_anomaly = False
            score = 0.0

        return is_anomaly, float(score), self.model_id