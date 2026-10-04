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