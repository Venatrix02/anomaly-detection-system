import joblib
import logging
from database.connection import SessionLocal
from database.tables import ModelInfo

logger = logging.getLogger(__name__)

#cechy, których model oczekuje (identyczna kolejność jak w train_model.py)

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
    'finish_packets_count'
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
        session = SessionLocal()
        try:

            #znalezienie modelu, który ma flagę is_active=True

            active_model_info = session.query(ModelInfo).filter(ModelInfo.is_active == True).first()
            
            if not active_model_info:
                logger.warning("Brak aktywnego modelu w bazie. Używam domyślnego: Isolation Forest.")
                self.algorithm_type = "IsolationForest"
                self.model_id = 1
            else:
                self.algorithm_type = active_model_info.algorithm_type
                self.model_id = active_model_info.id
            
            logger.info(f"Ładowanie modelu: {self.algorithm_type} (ID: {self.model_id})")
            
            #wczytanie odpowiedniego pliku .pkl w zależności od typu algorytmu

            if self.algorithm_type == "IsolationForest":
                self.model = joblib.load("models/isolation_forest.pkl")
            elif self.algorithm_type == "OneClassSVM":
                loaded_data = joblib.load("models/one_class_svm.pkl")
                self.model = loaded_data['model']
                self.scaler = loaded_data['scaler']
            elif self.algorithm_type == "Threshold":
                self.threshold_stats = joblib.load("models/threshold_method.pkl")
            else:
                logger.error(f"Nieznany typ algorytmu: {self.algorithm_type}")
                
        except Exception as e:
            logger.error(f"Błąd podczas ładowania modelu: {e}")
        finally:
            session.close()

    #sprawdzanie, czy podane cechy są anomalią

    def predict(self, metric_data):

        #przygotowanie wektora cech w odpowiedniej kolejności

        X = [[metric_data.get(col, 0) for col in FEATURE_COLUMNS]]
        
        if self.algorithm_type == "IsolationForest":

            #Isolation Forest zwraca 1 dla normalnych, -1 dla anomalii

            prediction = self.model.predict(X)[0]

            #score: im bardziej ujemny, tym większa anomalia

            score = self.model.score_samples(X)[0]
            is_anomaly = (prediction == -1)
            
        elif self.algorithm_type == "OneClassSVM":

            #SVM zwraca 1 dla normalnych, -1 dla anomalii

            X_scaled = self.scaler.transform(X)
            prediction = self.model.predict(X_scaled)[0]
            score = self.model.decision_function(X_scaled)[0]
            is_anomaly = (prediction == -1)
            
        elif self.algorithm_type == "Threshold":

            #Metoda progowa: sprawdzamy, czy którakolwiek cecha wykracza poza mean ± 3*std

            is_anomaly = False
            max_deviation = 0
            means = self.threshold_stats['means']
            stds = self.threshold_stats['stds']
            n_sigmas = self.threshold_stats['n_sigmas']
            
            for i, col in enumerate(FEATURE_COLUMNS):
                val = X[0][i]
                mean = means.iloc[i] if hasattr(means, 'iloc') else means[i]
                std = stds.iloc[i] if hasattr(stds, 'iloc') else stds[i]
                
                #obliczanie, ile odchyleń standardowych wynosi odchylenie wartości

                deviation = abs(val - mean) / std if std > 0 else 0
                if deviation > max_deviation:
                    max_deviation = deviation
                
                if deviation > n_sigmas:
                    is_anomaly = True
            
            score = -max_deviation #dla metody progowej score to maksymalne odchylenie (im wyższe, tym gorzej)
            
        else:
            is_anomaly = False
            score = 0.0

        return is_anomaly, float(score), self.model_id