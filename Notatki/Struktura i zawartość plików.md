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

### inne pliki
- create_tables.py
- main.py
- requirements.txt
- traffic_generator.py
- train_model.py

# Zawartość poszczególnych plików

## **sniffer.py**

```py

import logging
import time
from scapy.all import sniff, IP, TCP, UDP

logger = logging.getLogger(__name__)

IFACE = "wlo1" #karta sieciowa, z której zbieram ruch

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

## **connection.py**

import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

#wczytanie danych logowania do bazy danych z pliku .env

load_dotenv()

user = os.getenv("DB_USER")
password = os.getenv("DB_PASSWORD")
host = os.getenv("DB_HOST")
name = os.getenv("DB_NAME")

#tworzenie połączenia z bazą MySQL

engine = create_engine(f"mysql+pymysql://{user}:{password}@{host}/{name}")
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

```

## **repository.py**

```py

import logging
from database.connection import SessionLocal
from database.tables import NetworkMetric, SystemLog

logger = logging.getLogger(__name__)

#zapisanie jednego wpisu do logu w bazie danych

def save_log(session, level, message):
    log = SystemLog(log_level=level, message=message)
    session.add(log)
    session.commit()

#zapisanie jednego podsumowania ruchu sieciowego do bazy danych

def save_metric(metric_data):
    if not metric_data:
        return

    session = SessionLocal()

    try:
        metric = NetworkMetric(**metric_data)
        session.add(metric)
        session.commit()

        msg = (
            f"Metric saved: {metric_data['packets_count']} packets, "
            f"{metric_data['unique_ips']} unique IPs"
        )
        logger.info(msg)
        save_log(session, "INFO", msg)

    except Exception as e:
        session.rollback()
        logger.error(f"Error saving metric: {e}")
        save_log(session, "ERROR", str(e))

    finally:
        session.close()

```

## **tables.py**

```py

from sqlalchemy import Column, Integer, String, Float, Double, DateTime, Boolean, Text, ForeignKey
from datetime import datetime
from .connection import Base

#tabela z podsumowaniami ruchu sieciowego (jedno podsumowanie dla każdego okresu czasu - co 10 sekund ruchu)

class NetworkMetric(Base):
    __tablename__ = "network_metrics"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

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

#tabela z informacjami o modelu uczenia maszynowego wykrywającego anomalie

class ModelInfo(Base):
    __tablename__ = "model_info"

    id = Column(Integer, primary_key=True)
    model_name = Column(String(100))
    algorithm_type = Column(String(50))
    training_date = Column(DateTime)
    parameters = Column(Text)
    accuracy = Column(Float)
    is_active = Column(Boolean, default=False)

#tabela z wykrytymi anomaliami w ruchu sieciowym

class Anomaly(Base):
    __tablename__ = "anomalies"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    anomaly_score = Column(Float)
    severity_level = Column(String(10))
    description = Column(Text)
    metric_id = Column(Integer, ForeignKey("network_metrics.id"))
    model_id = Column(Integer, ForeignKey("model_info.id"))

#tabela z alertami generowanymi w przypadku wykrycia anomalii

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    anomaly_id = Column(Integer, ForeignKey("anomalies.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String(20), default="new")

#tabela z użytkownikami systemu i ich danymi logowania

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True)
    password_hash = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    is_active = Column(Boolean, default=True)

#tabela z raportami

class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True)
    generated_at = Column(DateTime, default=datetime.utcnow)
    period_start = Column(DateTime)
    period_end = Column(DateTime)
    generated_by = Column(Integer, ForeignKey("users.id"))
    file_path = Column(String(255))
    summary = Column(Text)

#tabela z logami systemowymi

class SystemLog(Base):
    __tablename__ = "system_logs"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    log_level = Column(String(10))
    message = Column(Text)

```

## **aggregator.py**

```py

from collections import Counter

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

#liczenie, ile jest różnych połączeń (unikalnych kompinacji adresów IP, portów i protokołu)

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
        p["dst_port"] for p in packet_list if p["dst_port"] != 0 #pominięcie 0, które oznacza brak portu
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
        "finish_packets_count": finish_packets_count
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

## **main.py**

```py

import time
import logging

from collector.sniffer import capture_packets
from collector.window_manager import SlidingWindow
from features.aggregator import aggregate_packets
from database.repository import save_metric

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
                save_metric(metric_data)

            last_aggregation = now

#użytkownik sam zatrzymał program (Ctrl+C)

except KeyboardInterrupt:
    logger.info("System stopped by user.")
    print("\nSystem stopped.")

#zapisywanie błędów do logu w przypadku nieoczekiwanych wyjątków

except Exception as e:
    logger.error(f"Unexpected error in main loop: {e}")

```

## **requirements.txt**

scapy==2.7.0  
SQLAlchemy==2.0.48  
python-dotenv==1.2.2  
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
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

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
    
    logger.info("Uruchamianie przeglądarki Chrome...")
    driver = webdriver.Chrome(
        service=Service(ChromeDriverManager().install()),
        options=chrome_options
    )
    
    end_time = time.time() + (duration_hours * 3600)
    visits_count = 0
    start_time = time.time()
    
    logger.info(f"Generowanie ruchu rozpoczęte na {duration_hours} godzin(y)...")
    
    try:
        while time.time() < end_time:

            #wybór losowej strony

            url = random.choice(WEBSITES)
            
            try:
                logger.info(f"Odwiedzam: {url}")
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
                                logger.info(f"  → Klikam link: {href[:80]}")
                                driver.get(href)
                                visits_count += 1
                                time.sleep(random.uniform(3, 15))
                    except Exception:
                        pass  #ignorowanie błędów klikania
                
                #losowa przerwa między stronami (między 2 a 10 sekund)

                pause = random.uniform(2, 10)
                time.sleep(pause)
                
                #wyświetlenie postępu co 10 odwiedzin

                if visits_count % 10 == 0:
                    elapsed = (time.time() - start_time) / 60
                    logger.info(f"Postęp: {visits_count} odwiedzin w {elapsed:.1f} minut")
                
            except Exception as e:
                logger.warning(f"Błąd podczas odwiedzania {url}: {e}")
                time.sleep(5)
    
    except KeyboardInterrupt:
        logger.info("Generowanie ruchu zatrzymane przez użytkownika.")
    finally:
        driver.quit()
        elapsed_total = (time.time() - start_time) / 60
        logger.info(f"Generowanie ruchu zakończone. Łącznie odwiedzin: {visits_count} w {elapsed_total:.1f} minut")


if __name__ == "__main__":
    generate_traffic(duration_hours=2) #generowanie ruchu przez 2 godziny

```
## **train_model.py**

```py

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
import joblib
import logging
from datetime import datetime
from database.connection import SessionLocal
from database.tables import NetworkMetric, ModelInfo

#konfiguracja logowania
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

MODELS_DIR = "models" #katalog, w którym zapisywane są wytrenowane modele

#cechy używane do trenowania modeli (takie jak w tabelinetwork_metrics)

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

#pobieranie danych z bazy i zamiana ich na format DataFrame

def load_data_from_db():
    logger.info("Łączenie z bazą danych...")
    session = SessionLocal()
    
    try:
        metrics = session.query(NetworkMetric).all()
        logger.info(f"Pobrano {len(metrics)} rekordów z bazy.")
        
        if len(metrics) < 500:
            logger.warning("Zbyt mało danych! Zalecane minimum to 1000 rekordów.")
        
        data = []
        for m in metrics:
            row = {col: getattr(m, col) for col in FEATURE_COLUMNS}
            data.append(row)
        
        df = pd.DataFrame(data)
        return df
    
    except Exception as e:
        logger.error(f"Błąd podczas pobierania danych: {e}")
        raise
    finally:
        session.close()

#trenowanie modelu Isolation Forest i zapis do pliku

def train_isolation_forest(X):
    logger.info("Trenowanie modelu Isolation Forest...")
    
    model = IsolationForest(
        n_estimators=100,
        contamination=0.01,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X)
    
    model_path = f"{MODELS_DIR}/isolation_forest.pkl"
    joblib.dump(model, model_path)
    logger.info(f"Isolation Forest zapisany jako '{model_path}'")
    
    return model, model_path

#trenowanie modelu One-Class SVM (z wcześniejszą standaryzacją danych) i zapis do pliku

def train_one_class_svm(X):
    logger.info("Trenowanie modelu One-Class SVM...")
    
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
    logger.info(f"One-Class SVM zapisany jako '{model_path}'")
    
    return model, model_path

#trenowanie metody progowej (obliczanie średniej i odchylenia standardowego) i zapis do pliku

def train_threshold_method(X):
    logger.info("Trenowanie metody progowej...")
    
    means = X.mean(axis=0)
    stds = X.std(axis=0)
    
    #zabezpieczenie przed dzieleniem przez zero, jeśli odchylenie wynosi 0

    stds = stds.replace(0, 1e-6) if isinstance(stds, pd.Series) else np.where(stds == 0, 1e-6, stds) 
    
    model_path = f"{MODELS_DIR}/threshold_method.pkl"
    joblib.dump({
        'means': means,
        'stds': stds,
        'n_sigmas': 3
    }, model_path)
    logger.info(f"Metoda progowa zapisana jako '{model_path}'")
    
    return model_path

#zapisywanie informacji o wytrenowanym modelu do tabeli model_info w bazie danych

def save_model_info_to_db(model_name, algorithm_type, parameters, is_active=False):
    session = SessionLocal()
    try:

        #jeśli model ma być aktywny najpierw dezaktywowane są wszystkie pozostałe

        if is_active:
            session.query(ModelInfo).update({ModelInfo.is_active: False})
        
        model_info = ModelInfo(
            model_name=model_name,
            algorithm_type=algorithm_type,
            training_date=datetime.utcnow(),
            parameters=parameters,
            accuracy=None,
            is_active=is_active
        )
        session.add(model_info)
        session.commit()
        logger.info(f"Informacje o modelu '{model_name}' zapisane w bazie")
    except Exception as e:
        session.rollback()
        logger.error(f"Błąd podczas zapisywania informacji o modelu: {e}")
    finally:
        session.close()

#główna funkcja trenująca wszystkie 3 modele po kolei

def train_all_models():
    logger.info("=" * 60)
    logger.info("ROZPOCZĘCIE TRENINGU MODELI")
    logger.info("=" * 60)
    
    #pobranie danych z bazy

    df = load_data_from_db()
    
    if df.empty:
        logger.error("Brak danych do trenowania.")
        return
    
    #sprawdzenie, czy wszystkie wymagane kolumny są dostępne w pobranych danych

    missing_cols = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing_cols:
        logger.error(f"Brakujące kolumny w bazie: {missing_cols}")
        return
    
    X = df[FEATURE_COLUMNS]
    logger.info(f"Macierz cech: {X.shape[0]} wierszy × {X.shape[1]} cech")
    
    #trenowanie i zapis modelu 1: Isolation Forest

    model_if, path_if = train_isolation_forest(X)
    save_model_info_to_db(
        model_name="Isolation Forest v1",
        algorithm_type="IsolationForest",
        parameters="n_estimators=100, contamination=0.01, random_state=42",
        is_active=True
    )
    
    #trenowanie i zapis modelu 2: One-Class SVM

    model_svm, path_svm = train_one_class_svm(X)
    save_model_info_to_db(
        model_name="One-Class SVM v1",
        algorithm_type="OneClassSVM",
        parameters="kernel=rbf, gamma=scale, nu=0.01",
        is_active=False
    )
    
    #trenowanie i zapis modelu 3: Metoda progowa

    path_threshold = train_threshold_method(X)
    save_model_info_to_db(
        model_name="Threshold Method v1",
        algorithm_type="Threshold",
        parameters="n_sigmas=3 (mean ± 3*std)",
        is_active=False
    )
    
    logger.info("=" * 60)
    logger.info("WSZYSTKIE 3 MODELE ZOSTAŁY WYTRENOWANE")
    logger.info("=" * 60)
    logger.info(f"Pliki modeli zapisane w folderze: {MODELS_DIR}/")

#uruchomienie trenowania wszystkich modeli

if __name__ == "__main__":
    train_all_models()

```