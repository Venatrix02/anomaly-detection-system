# Struktura plików projektu

### folder collector
- sniffer.py
- window_manager.py

### folder database
- conncection.py
- repository.py
- tables.py

### folder features
- aggregator.py

### folder models
- isolation_forest.pkl
- one_class_svm.pkl
- threshold_method.pkl

### folder paper
- generate_paper_figures.py

### inne pliki
- create_tables.py
- detector.py
- main.py
- requirements.txt
- traffic_generator.py
- train_model.py
- system.log

# Zawartość poszczególnych plików

## **sniffer.py**

```py

import logging
import time
import os
from scapy.all import sniff, IP, TCP, UDP
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

IFACE = os.getenv("SNIFFER_IFACE", "wlo1") #interfejs sieciowy pobierany z .env

#wyciąganie najważniejszych informacji z pakietów

def process_packet(packet, packet_list):
    if IP in packet:
        tcp_flags = str(packet[TCP].flags) if TCP in packet else ""
        packet_list.append({
            "timestamp": time.time(),
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "size": len(packet),
            "protocol": "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER",
            "src_port": packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0,
            "dst_port": packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0,
            "tcp_flags": tcp_flags
        })

#tworzenie listy pakietów zebranych w czasie 1 sekundy

def capture_packets(duration=1):
    packet_list = []
    try:
        sniff(
            iface=IFACE,
            filter="tcp or udp",
            timeout=duration,
            prn=lambda pkt: process_packet(pkt, packet_list),
            store=False
        )
        logger.info(f"Captured {len(packet_list)} packets")
    except Exception as e:
        logger.error(f"Error during packet capture: {e}")
    return packet_list

#bezpieczne zatrzymanie sniffera

def stop_sniffer():
    logger.info("Sniffer will stop after current capture cycle.")

```

## **window_manager.py**

```py

class SlidingWindow:

#tworzenie okna czasowego o podanej długości w sekundach

    def __init__(self, window_size): 
        self.window_size = window_size
        self.buffer = []

#dodawanie nowych pakietów do okna i usuwanie starych

    def add_packets(self, packets, current_time): 
        self.buffer.extend(packets)
        self.buffer = [
            p for p in self.buffer
            if current_time - p["timestamp"] <= self.window_size
        ]

    def get_packets(self):
        return self.buffer

```

## **repository.py**

```py

import logging
from datetime import datetime, timezone, timedelta
from database.connection import SessionLocal
from database.tables import NetworkMetric, SystemLog, Alert, Anomaly

logger = logging.getLogger(__name__)

#zapisanie jednego wpisu do logu w bazie danych

def save_log(session, level, message):
    log = SystemLog(log_level=level, message=message)
    session.add(log)
    session.commit()

#zapisanie jednego podsumowania ruchu sieciowego do bazy danych
def save_metric(metric_data):
    if not metric_data:
        return None
    with SessionLocal() as session:
        try:
            metric = NetworkMetric(**metric_data)
            session.add(metric)
            session.commit()
            session.refresh(metric)
            msg = (
                f"Metric saved: {metric_data['packets_count']} packets, "
                f"{metric_data['unique_ips']} unique IPs"
            )
            logger.info(msg)
            save_log(session, "INFO", msg)
            return metric.id
        except Exception as e:
            session.rollback()
            logger.error("Error saving metric: " + str(e))
            save_log(session, "ERROR", str(e))
            return None

#zapisanie wykrytej anomalii do bazy danych

def save_anomaly(anomaly_data):
    if not anomaly_data:
        return None
    with SessionLocal() as session:
        try:
            anomaly = Anomaly(**anomaly_data)
            session.add(anomaly)
            session.commit()
            session.refresh(anomaly)
            logger.info("Anomaly saved: score=" + str(anomaly_data['anomaly_score']) + ", severity=" + str(anomaly_data['severity_level']))
            return anomaly.id
        except Exception as e:
            session.rollback()
            logger.error("Error saving anomaly: " + str(e))
            return None

#zapisanie alertu do bazy danych, z uwzględnieniem cooldownu dla alertów o tym samym poziomie istotności

def save_alert(anomaly_id, severity_level):
    if not anomaly_id:
        return
    with SessionLocal() as session:
        try:

            #sprawdzanie, czy istnieje już alert o tym samym poziomie istotności w ciągu ostatnich 5 minut

            recent_alert = session.query(Alert).join(Anomaly).filter(
                Anomaly.severity_level == severity_level,
                Alert.status == "new",
                Alert.created_at >= datetime.now(timezone.utc) - timedelta(minutes=5)
            ).first()

            if recent_alert:

                #aktualizacja czasu ostatniego wystąpienia alertu, jeśli istnieje już alert o tym samym poziomie istotności
                
                recent_alert.last_seen = datetime.now(timezone.utc)
                session.commit()
                logger.info("Alert cooldown: updated last_seen for severity " + severity_level)
            else:
                
                #tworzenie nowego alertu
                
                new_alert = Alert(
                    anomaly_id=anomaly_id,
                    status="new",
                    created_at=datetime.now(timezone.utc),
                    last_seen=datetime.now(timezone.utc)
                )
                session.add(new_alert)
                session.commit()
                logger.info("Alert saved for severity: " + severity_level)
        except Exception as e:
            session.rollback()
            logger.error("Error saving alert: " + str(e))

#wyznaczanie poziomu istotności anomalii na podstawie anomaly score

def determine_severity(score):

    #im bardziej ujemnty score, tym większa anomalia

    if score < -0.5:
        return "high"
    elif score < -0.2:
        return "medium"
    else:
        return "low"

```

## **tables.py**

```py

from sqlalchemy import Column, Integer, String, Float, Double, DateTime, Boolean, Text, ForeignKey
from datetime import datetime, timezone
from .connection import Base

#tabela z podsumowaniami ruchu sieciowego

class NetworkMetric(Base):
    __tablename__ = "network_metrics"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    window_start = Column(Double)
    window_end = Column(Double)
    packets_count = Column(Integer)
    unique_ips = Column(Integer)
    unique_ports = Column(Integer)
    avg_packet_size = Column(Float)
    tcp_ratio = Column(Float)
    udp_ratio = Column(Float)
    other_ratio = Column(Float)
    unique_connections = Column(Integer)
    dominant_port = Column(Integer)
    synchronization_packets_count = Column(Integer)
    acknowledgment_packets_count = Column(Integer)
    reset_packets_count = Column(Integer)
    finish_packets_count = Column(Integer)
    packet_size_std = Column(Float, default=0.0)
    syn_to_ack_ratio = Column(Float, default=0.0)

#tabela z informacjami o modelu ML

class ModelInfo(Base):
    __tablename__ = "model_info"
    id = Column(Integer, primary_key=True)
    model_name = Column(String(100))
    algorithm_type = Column(String(50))
    training_date = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    parameters = Column(Text)
    accuracy = Column(Float)
    is_active = Column(Boolean, default=False, index=True)

#tabela z wykrytymi anomaliami

class Anomaly(Base):
    __tablename__ = "anomalies"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    anomaly_score = Column(Float)
    severity_level = Column(String(10), index=True)
    description = Column(Text)
    metric_id = Column(Integer, ForeignKey("network_metrics.id"))
    model_id = Column(Integer, ForeignKey("model_info.id"))

#tabela z alertami

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    anomaly_id = Column(Integer, ForeignKey("anomalies.id"))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    status = Column(String(20), default="new", index=True)

#tabela z użytkownikami

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True)
    password_hash = Column(String(255))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = Column(DateTime)
    is_active = Column(Boolean, default=True)

#tabela z raportami

class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True)
    generated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    period_start = Column(DateTime)
    period_end = Column(DateTime)
    generated_by = Column(Integer, ForeignKey("users.id"))
    file_path = Column(String(255))
    summary = Column(Text)

#tabela z logami systemowymi

class SystemLog(Base):
    __tablename__ = "system_logs"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    log_level = Column(String(10))
    message = Column(Text)

```

## **aggregator.py**

```py

from collections import Counter
import numpy as np

#tworzenie podsumowania z listy pakietów

def aggregate_packets(packet_list):
    if not packet_list:
        return None

    total_packets = len(packet_list)
    unique_ips = len(
        set(p["src_ip"] for p in packet_list) |
        set(p["dst_ip"] for p in packet_list)
    )
    unique_ports = len(
        set(p["src_port"] for p in packet_list) |
        set(p["dst_port"] for p in packet_list)
    )
    average_packet_size = sum(p["size"] for p in packet_list) / total_packets

    tcp_packets = sum(1 for p in packet_list if p["protocol"] == "TCP")
    udp_packets = sum(1 for p in packet_list if p["protocol"] == "UDP")
    other_packets = sum(1 for p in packet_list if p["protocol"] == "OTHER")

    #liczenie, ile jest różnych połączeń

    unique_connections = len(
        set(
            (
                p["src_ip"],
                p["dst_ip"],
                p["src_port"],
                p["dst_port"],
                p["protocol"]
            )
            for p in packet_list
        )
    )

    #szukanie portu, który pojawiał się najczęściej

    destination_port_counter = Counter(
        p["dst_port"] for p in packet_list if p["dst_port"] != 0
    )
    most_common_port = destination_port_counter.most_common(1)
    dominant_destination_port = most_common_port[0][0] if most_common_port else 0

    #liczenie różnych sygnałów TCP

    synchronization_packets_count = sum(
        1 for p in packet_list
        if p["tcp_flags"] and "S" in p["tcp_flags"] and "A" not in p["tcp_flags"]
    )
    acknowledgment_packets_count = sum(
        1 for p in packet_list
        if p["tcp_flags"] and "A" in p["tcp_flags"]
    )
    reset_packets_count = sum(
        1 for p in packet_list
        if p["tcp_flags"] and "R" in p["tcp_flags"]
    )
    finish_packets_count = sum(
        1 for p in packet_list
        if p["tcp_flags"] and "F" in p["tcp_flags"]
    )

    #odchylenie standardowe rozmiaru pakietu

    packet_sizes = [p["size"] for p in packet_list]
    packet_size_std = float(np.std(packet_sizes)) if packet_sizes else 0.0

    #stosunek SYN do ACK (wykrywanie SYN Flood)
 
    if acknowledgment_packets_count > 0:
        syn_to_ack_ratio = synchronization_packets_count / acknowledgment_packets_count
    else:
        syn_to_ack_ratio = float(synchronization_packets_count)

    window_start = min(p["timestamp"] for p in packet_list)
    window_end = max(p["timestamp"] for p in packet_list)

    return {
        "window_start": window_start,
        "window_end": window_end,
        "packets_count": total_packets,
        "unique_ips": unique_ips,
        "unique_ports": unique_ports,
        "avg_packet_size": round(average_packet_size, 2),
        "tcp_ratio": round(tcp_packets / total_packets, 2),
        "udp_ratio": round(udp_packets / total_packets, 2),
        "other_ratio": round(other_packets / total_packets, 2),
        "unique_connections": unique_connections,
        "dominant_port": dominant_destination_port,
        "synchronization_packets_count": synchronization_packets_count,
        "acknowledgment_packets_count": acknowledgment_packets_count,
        "reset_packets_count": reset_packets_count,
        "finish_packets_count": finish_packets_count,
        "packet_size_std": round(packet_size_std, 2),
        "syn_to_ack_ratio": round(syn_to_ack_ratio, 4)
    }

```

## **create tables.py**

```py

from database.connection import engine, Base
from database.tables import *

#tworzenie w bazie wszystkich tabeli opisanych w pliku tables.py

Base.metadata.create_all(engine)

print("All tables have been created")

```

## **detector.py**

```py

import joblib
import logging
import pandas as pd
from database.connection import SessionLocal
from database.tables import ModelInfo

logger = logging.getLogger(__name__)

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
        session = SessionLocal()
        try:

            #znalezienie modelu, który ma flagę is_active=True

            active_model_info = session.query(ModelInfo).filter(ModelInfo.is_active == True).first()
            if not active_model_info:
                logger.warning("No active model in the database. Using default: Isolation Forest.")
                self.algorithm_type = "IsolationForest"
                self.model_id = 1
            else:
                self.algorithm_type = active_model_info.algorithm_type
                self.model_id = active_model_info.id
            logger.info(f"Loading model: {self.algorithm_type} (ID: {self.model_id})")
            
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
                logger.error(f"Unknown algorithm type: {self.algorithm_type}")
        except Exception as e:
            logger.error(f"Error loading model: {e}")
        finally:
            session.close()

    #sprawdzanie, czy podane cechy są anomalią

    def predict(self, metric_data):

        #przygotowanie wektora cech w odpowiedniej kolejności

        X = pd.DataFrame([metric_data]).reindex(columns=FEATURE_COLUMNS, fill_value=0)
        
        if self.algorithm_type == "IsolationForest":

            #Isolation Forest zwraca 1 dla normalnych, -1 dla anomalii

            prediction = self.model.predict(X)[0]

            #score - im bardziej ujemny, tym większa anomalia

            score = self.model.score_samples(X)[0]
            is_anomaly = (prediction == -1)
            
        elif self.algorithm_type == "OneClassSVM":

            #SVM zwraca 1 dla normalnych, -1 dla anomalii

            X_scaled = self.scaler.transform(X)
            prediction = self.model.predict(X_scaled)[0]
            score = self.model.decision_function(X_scaled)[0]
            is_anomaly = (prediction == -1)
            
        elif self.algorithm_type == "Threshold":

            #metoda progowa - sprawdzanie czy którakolwiek cecha wykracza poza mean ± n_sigmas * std

            is_anomaly = False
            max_deviation = 0
            means = self.threshold_stats['means']
            stds = self.threshold_stats['stds']
            n_sigmas = self.threshold_stats['n_sigmas']
            
            for i, col in enumerate(FEATURE_COLUMNS):
                val = X.iloc[0][i]

                if hasattr(means, 'get'):
                    mean = means.get(col, 0)
                    std = stds.get(col, 1)
                elif hasattr(means, 'iloc'):
                    mean = means.iloc[i]
                    std = stds.iloc[i]
                else:
                    mean = means[i] if i < len(means) else 0
                    std = stds[i] if i < len(stds) else 1
                
                #obliczanie, ile odchyleń standardowych wynosi odchylenie wartości
                
                deviation = abs(val - mean) / std if std > 0 else 0
                if deviation > max_deviation:
                    max_deviation = deviation
                if deviation > n_sigmas:
                    is_anomaly = True
                    
            score = -max_deviation  #dla metody progowej score to maksymalne odchylenie
            
        else:
            is_anomaly = False
            score = 0.0
            
        return is_anomaly, float(score), self.model_id
```

## **requirements.txt**

scapy==2.7.0  
SQLAlchemy==2.0.48  
python-dotenv==1.2.  
PyMySQL==1.1.1  
pandas==3.0.1  
numpy==2.4.2  
scipy==1.17.1  
scikit-learn==1.8.0  
joblib==1.5.3  
Django==6.0.3  
django-cors-headers==4.9.0  
fastapi==0.135.1  
uvicorn==0.41.0  
selenium==4.31.0  
webdriver-manager==4.0.2

## **traffic_generator.py**

```py

import time
import random
import logging
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

#konfiguracja logowania

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

#lista stron

WEBSITES = [
    "https://www.reddit.com",
    "https://www.pinterest.com",
    "https://www.youtube.com",
    "https://shinden.pl",
    "https://www.webtoons.com",
    "https://lubimyczytac.pl",
    "https://www.wikipedia.org",
    "https://www.khanacademy.org",
    "https://github.com",
    "https://stackoverflow.com",
    "https://developer.mozilla.org",
    "https://www.canva.com",
    "https://www.bbc.com",
    "https://www.onet.pl",
    "https://news.ycombinator.com",
    "https://www.allegro.pl",
]


def generate_traffic(duration_hours=2):

    #konfiguracja przeglądarki Chrome

    chrome_options = Options()
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")
    chrome_options.add_argument("--window-size=1920,1080")
    prefs = {"profile.managed_default_content_settings.images": 2}
    chrome_options.add_experimental_option("prefs", prefs)

    logger.info("Starting Chrome browser...")
    try:
        driver = webdriver.Chrome(options=chrome_options)
    except Exception as e:
        logger.error(f"Failed to start Chrome: {e}")
        logger.info("Trying alternative method...")
        chrome_options = Options()
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        driver = webdriver.Chrome(options=chrome_options)

    end_time = time.time() + (duration_hours * 3600)
    visits_count = 0
    start_time = time.time()
    logger.info(f"Traffic generation started for {duration_hours} hour(s)...")

    try:
        while time.time() < end_time:

            #wybór losowej strony

            url = random.choice(WEBSITES)
            try:
                logger.info(f"Visiting:  {url}")
                driver.get(url)
                visits_count += 1

                #losowy czas czytania strony (między 5 a 30 sekund)

                reading_time = random.uniform(5, 30)
                time.sleep(reading_time)

                #kliknięcie (czasami) w losowy link na stronie (30% szans)

                if random.random() < 0.3:
                    try:
                        links = driver.find_elements("tag name", "a")
                        if links:
                            random_link = random.choice(links[:20])
                            href = random_link.get_attribute("href")
                            if href and href.startswith("http"):
                                logger.info(f"  -> Clicking link: {href[:80]}")
                                driver.get(href)
                                visits_count += 1
                                time.sleep(random.uniform(3, 15))
                    except Exception:
                        pass  #ignorowanie błędów klikania

                #losowa przerwa między stronami (miedzy 2 a 10 sekund)

                pause = random.uniform(2, 10)
                time.sleep(pause)

                #wyświetlenie postępu co 10 odwiedzin

                if visits_count % 10 == 0:
                    elapsed = (time.time() - start_time) / 60
                    logger.info(f"Progress: {visits_count} visits in {elapsed:.1f} minutes")
            except Exception as e:
                logger.warning(f"Error while visiting {url}: {e}")
                time.sleep(5)

    except KeyboardInterrupt:
        logger.info("Traffic generation stopped by user.")
    finally:
        driver.quit()
        elapsed_total = (time.time() - start_time) / 60
        logger.info(f"Traffic generation completed. Total visits: {visits_count} in {elapsed_total:.1f} minutes")

if __name__ == "__main__":
    generate_traffic(duration_hours=0.25)

```
## **train_model.py**

```py

import pandas as pd
import numpy as np
import json
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
import joblib
import logging
from datetime import datetime, timezone
from database.connection import SessionLocal
from database.tables import NetworkMetric, ModelInfo

#konfiguracja logowania

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

MODELS_DIR = "models"

#cechy używane do trenowania modeli

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

#pobieranie danych z bazy

def load_data_from_db():
    logger.info("Connecting to the database...")
    with SessionLocal() as session:
        try:
            metrics = session.query(NetworkMetric).all()
            logger.info(f"Fetched  {len(metrics)} records from the database.")
            if len(metrics) < 500:
                logger.warning("Too little data! Recommended minimum is 1000 records.")
            data = []
            for m in metrics:
                row = {col: getattr(m, col) for col in FEATURE_COLUMNS}
                data.append(row)
            df = pd.DataFrame(data)
            return df
        except Exception as e:
            logger.error(f"Error while fetching data: {e}")
            raise

#trenowanie modelu Isolation Forest

def train_isolation_forest(X):
    logger.info("Training Isolation Forest model...")
    model = IsolationForest(
        n_estimators=100,
        contamination=0.01,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X)
    model_path = f"{MODELS_DIR}/isolation_forest.pkl"
    joblib.dump(model, model_path)
    logger.info(f"Isolation Forest saved as '{model_path}'")
    return model, model_path

#trenowanie One-Class SVM

def train_one_class_svm(X):
    logger.info("Training One-Class SVM model...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    model = OneClassSVM(
        kernel='rbf',
        gamma='scale',
        nu=0.01
    )
    model.fit(X_scaled)
    model_path = f"{MODELS_DIR}/one_class_svm.pkl"
    joblib.dump({
        'model': model,
        'scaler': scaler
    }, model_path)
    logger.info(f"One-Class SVM saved as '{model_path}'")
    return model, model_path

#trenowanie metody progowej

def train_threshold_method(X):
    logger.info("Training threshold method...")
    means = X.mean(axis=0)
    stds = X.std(axis=0)
    stds = stds.replace(0, 1e-6) if isinstance(stds, pd.Series) else np.where(stds == 0, 1e-6, stds)
    model_path = f"{MODELS_DIR}/threshold_method.pkl"
    joblib.dump({
        'means': means,
        'stds': stds,
        'n_sigmas': 3
    }, model_path)
    logger.info(f"Threshold method saved as '{model_path}'")
    return model_path

#zapisywanie informacji o modelu do bazy

def save_model_info_to_db(model_name, algorithm_type, parameters, is_active=False):
    with SessionLocal() as session:
        try:
            if is_active:
                session.query(ModelInfo).update({ModelInfo.is_active: False})
            model_info = ModelInfo(
                model_name=model_name,
                algorithm_type=algorithm_type,
                training_date=datetime.now(timezone.utc),
                parameters=parameters,
                accuracy=None,
                is_active=is_active
            )
            session.add(model_info)
            session.commit()
            logger.info(f"Model information for '{model_name}' saved to the database")
        except Exception as e:
            session.rollback()
            logger.error(f"Error while saving model information: {e}")

#zapis metadanych modelu do JSON

def save_model_metadata(X):
    metadata = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "samples_used": len(X),
        "features": list(X.columns),
        "feature_count": len(X.columns)
    }
    with open(f"{MODELS_DIR}/model_metadata.json", "w") as f:
        json.dump(metadata, f, indent=4)
    logger.info(f"Model metadata saved in '{MODELS_DIR}/model_metadata.json'")

#główna funkcja trenująca

def train_all_models():
    logger.info("=" * 60)
    logger.info("STARTING MODEL TRAINING")
    logger.info("=" * 60)

    df = load_data_from_db()
    if df.empty:
        logger.error("No data available for training.")
        return

    missing_cols = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing_cols:
        logger.error(f"Missing columns in database: {missing_cols}")
        return

    #czyszczenie danych

    initial_count = len(df)
    df = df[(df['packets_count'] >= 0) & (df['packets_count'] < 100000)]
    df = df.fillna(0)
    logger.info(f"Cleaned data: removed {initial_count - len(df)} records (measurement errors).")

    X = df[FEATURE_COLUMNS]
    logger.info(f"Feature matrix: {X.shape[0]} rows × {X.shape[1]} features")

    #zapis metadanych

    save_model_metadata(X)

    #trenowanie modeli
    
    model_if, path_if = train_isolation_forest(X)
    save_model_info_to_db(
        model_name="Isolation Forest v2",
        algorithm_type="IsolationForest",
        parameters="n_estimators=100, contamination=0.01, random_state=42",
        is_active=True
    )

    model_svm, path_svm = train_one_class_svm(X)
    save_model_info_to_db(
        model_name="One-Class SVM v2",
        algorithm_type="OneClassSVM",
        parameters="kernel=rbf, gamma=scale, nu=0.01",
        is_active=False
    )

    path_threshold = train_threshold_method(X)
    save_model_info_to_db(
        model_name="Threshold Method v2",
        algorithm_type="Threshold",
        parameters="n_sigmas=3 (mean ± 3*std)",
        is_active=False
    )

    logger.info("=" * 60)
    logger.info("ALL 3 MODELS HAVE BEEN TRAINED")
    logger.info("=" * 60)
    logger.info(f"Model files saved in folder: {MODELS_DIR}/")

if __name__ == "__main__":
    train_all_models()

```

## **generate_paper_figures.py**

```py

import os
import sys
import logging
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.connection import SessionLocal
from database.tables import Anomaly, ModelInfo, NetworkMetric

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

#pobieranie danych z bazy

def get_data_from_db():
    with SessionLocal() as session:
        anomalies = session.query(
            Anomaly.timestamp,
            ModelInfo.algorithm_type,
            Anomaly.anomaly_score,
            Anomaly.severity_level
        ).join(ModelInfo, Anomaly.model_id == ModelInfo.id).order_by(Anomaly.timestamp).all()

        df_anomalies = pd.DataFrame(anomalies, columns=[
            'timestamp', 'algorithm_type', 'anomaly_score', 'severity_level'
        ])

        metrics = session.query(
            NetworkMetric.timestamp,
            NetworkMetric.syn_to_ack_ratio
        ).order_by(NetworkMetric.timestamp).all()

        df_metrics = pd.DataFrame(metrics, columns=[
            'timestamp', 'syn_to_ack_ratio'
        ])

    logger.info(f"Retrieved {len(df_anomalies)} anomalies and {len(df_metrics)} metrics")
    return df_anomalies, df_metrics

#normalizacja czasu

def normalize_time(df_anomalies):
    df_anomalies['minutes_elapsed'] = df_anomalies.groupby('algorithm_type')['timestamp'].transform(
        lambda x: (x - x.min()).dt.total_seconds() / 60
    )
    return df_anomalies

#wykres 1 - subplots z oznaczeniem ataku

def plot_subplots_with_attack(df_anomalies):
    fig, axes = plt.subplots(3, 1, figsize=(14, 12), sharex=True)
    fig.suptitle('Anomaly Scores Over Time: Model Comparison (Normalized Time)', fontsize=16, fontweight='bold', y=0.98)
    
    models = ['IsolationForest', 'OneClassSVM', 'Threshold']
    colors = ['#1f77b4', '#ff7f0e', '#d62728']
    
    for i, model in enumerate(models):
        ax = axes[i]
        model_data = df_anomalies[df_anomalies['algorithm_type'] == model]
        
        if len(model_data) > 0:

            #obliczanie statystyk

            mean_score = model_data['anomaly_score'].mean()
            std_score = model_data['anomaly_score'].std()
            count = len(model_data)
            
            #rysowanie linii

            ax.plot(model_data['minutes_elapsed'], model_data['anomaly_score'], 
                    marker='.', linestyle='-', color=colors[i], markersize=6, linewidth=1.5,
                    label=f'n={count}, mean={mean_score:.3f}, std={std_score:.3f}')
            
            #oznaczenie momentu ataku (przy założeniu, że atak zaczyna się po 2 minutach dla IF, 1 min dla OC-SVM, 0 min dla Threshold)
            
            if model == 'IsolationForest':
                attack_time = 4.0  #szacunkowo na podstawie danych
            elif model == 'OneClassSVM':
                attack_time = 2.5
            else:
                attack_time = 0.5
            
            ax.axvline(x=attack_time, color='red', linestyle='--', linewidth=2, alpha=0.7, label='Attack Start')
            
            ax.set_ylabel('Anomaly Score', fontsize=12, fontweight='bold')
            ax.set_title(f'{model} (mean={mean_score:.3f}, std={std_score:.3f})', 
                        fontsize=13, fontweight='bold', loc='left', pad=10)
            ax.legend(loc='best', fontsize=9)
            ax.grid(True, alpha=0.3, linestyle=':')
            ax.set_xlim(left=0)
    
    axes[2].set_xlabel('Time elapsed from test start (minutes)', fontsize=12, fontweight='bold')
    plt.tight_layout(rect=[0, 0, 1, 0.96])
    plt.savefig('paper/figures/fig1_subplots_comparison.png', dpi=300, bbox_inches='tight')
    logger.info("Saved plot 1 (subplots): paper/figures/fig1_subplots_comparison.png")
    plt.close()

#wykres 2 - boxplot IF vs OC-SVM

def plot_boxplot_if_svm(df_anomalies):
    plt.figure(figsize=(10, 6))
    
    df_filtered = df_anomalies[df_anomalies['algorithm_type'].isin(['IsolationForest', 'OneClassSVM'])]
    
    sns.boxplot(
        data=df_filtered,
        x='algorithm_type',
        y='anomaly_score',
        palette="Set2",
        showfliers=True,
        width=0.6
    )
    
    plt.title('Distribution of Anomaly Scores: Isolation Forest vs. One-Class SVM', fontsize=14, fontweight='bold')
    plt.xlabel('Detection Model', fontsize=12, fontweight='bold')
    plt.ylabel('Anomaly Score', fontsize=12, fontweight='bold')
    plt.grid(True, axis='y', alpha=0.3, linestyle=':')
    plt.ylim(-1.0, 0.1)
    plt.tight_layout()
    plt.savefig('paper/figures/fig2_boxplot_if_svm.png', dpi=300, bbox_inches='tight')
    logger.info("Saved plot 2 (boxplot IF vs SVM): paper/figures/fig2_boxplot_if_svm.png")
    plt.close()

#wykres 3 - boxplot Threshold

def plot_boxplot_threshold(df_anomalies):
    plt.figure(figsize=(10, 6))
    
    df_threshold = df_anomalies[df_anomalies['algorithm_type'] == 'Threshold']
    
    sns.boxplot(
        data=df_threshold,
        x='algorithm_type',
        y='anomaly_score',
        palette="Set2",
        showfliers=True,
        width=0.6
    )
    
    plt.title('Distribution of Anomaly Scores: Threshold Method', fontsize=14, fontweight='bold')
    plt.xlabel('Detection Model', fontsize=12, fontweight='bold')
    plt.ylabel('Anomaly Score', fontsize=12, fontweight='bold')
    plt.grid(True, axis='y', alpha=0.3, linestyle=':')
    plt.tight_layout()
    plt.savefig('paper/figures/fig3_boxplot_threshold.png', dpi=300, bbox_inches='tight')
    logger.info("Saved plot 3 (boxplot Threshold): paper/figures/fig3_boxplot_threshold.png")
    plt.close()

#tabela statystyk

def generate_statistics_table(df_anomalies):
    stats = df_anomalies.groupby(['algorithm_type'])['anomaly_score'].agg([
        'count', 'mean', 'std', 'min', 'max'
    ]).round(4)

    stats.to_csv('paper/data/table1_statistics.csv')
    logger.info("Saved statistics table: paper/data/table1_statistics.csv")
    print("\nStatystyki:")
    print(stats)
    return stats

def generate_all():
    logger.info("Starting generation of plots for the paper...")

    os.makedirs('paper/figures', exist_ok=True)
    os.makedirs('paper/data', exist_ok=True)

    df_anomalies, df_metrics = get_data_from_db()

    if len(df_anomalies) == 0:
        logger.error("No data available in the database.")
        return

    #normalizacja czasu

    df_anomalies = normalize_time(df_anomalies)

    df_anomalies.to_csv('paper/data/anomalies_export.csv', index=False)
    logger.info("Saved data: paper/data/anomalies_export.csv")

    sns.set_theme(style="whitegrid", font="DejaVu Sans", rc={"axes.grid": True})
    plt.rcParams['figure.dpi'] = 300
    plt.rcParams['font.size'] = 11

    plot_subplots_with_attack(df_anomalies)
    plot_boxplot_if_svm(df_anomalies)
    plot_boxplot_threshold(df_anomalies)
    generate_statistics_table(df_anomalies)

    logger.info("Done! Check the paper/figures/ and paper/data/ folders")

if __name__ == "__main__":
    generate_all()

```