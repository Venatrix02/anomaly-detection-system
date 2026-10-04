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

#cechy używane do trenowania modeli (identyczna kolejność jak w detector.py)

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
    logger.info("Łączenie z bazą danych...")
    with SessionLocal() as session:
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

#trenowanie modelu Isolation Forest

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

#trenowanie One-Class SVM

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

#trenowanie metody progowej

def train_threshold_method(X):
    logger.info("Trenowanie metody progowej...")
    means = X.mean(axis=0)
    stds = X.std(axis=0)
    stds = stds.replace(0, 1e-6) if isinstance(stds, pd.Series) else np.where(stds == 0, 1e-6, stds)
    model_path = f"{MODELS_DIR}/threshold_method.pkl"
    joblib.dump({
        'means': means,
        'stds': stds,
        'n_sigmas': 3
    }, model_path)
    logger.info(f"Metoda progowa zapisana jako '{model_path}'")
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
            logger.info(f"Informacje o modelu '{model_name}' zapisane w bazie")
        except Exception as e:
            session.rollback()
            logger.error(f"Błąd podczas zapisywania informacji o modelu: {e}")

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
    logger.info(f"Metadane modelu zapisane w '{MODELS_DIR}/model_metadata.json'")

#główna funkcja trenująca

def train_all_models():
    logger.info("=" * 60)
    logger.info("ROZPOCZĘCIE TRENINGU MODELI")
    logger.info("=" * 60)

    df = load_data_from_db()
    if df.empty:
        logger.error("Brak danych do trenowania.")
        return

    missing_cols = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing_cols:
        logger.error(f"Brakujące kolumny w bazie: {missing_cols}")
        return

    #czyszczenie danych

    initial_count = len(df)
    df = df[(df['packets_count'] >= 0) & (df['packets_count'] < 100000)]
    df = df.fillna(0)
    logger.info(f"Wyczyszczono dane: usunięto {initial_count - len(df)} rekordów (błędy pomiaru).")

    X = df[FEATURE_COLUMNS]
    logger.info(f"Macierz cech: {X.shape[0]} wierszy × {X.shape[1]} cech")

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
    logger.info("WSZYSTKIE 3 MODELE ZOSTAŁY WYTRENOWANE")
    logger.info("=" * 60)
    logger.info(f"Pliki modeli zapisane w folderze: {MODELS_DIR}/")

if __name__ == "__main__":
    train_all_models()