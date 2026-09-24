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

#zapisanie wykrytej anomalii do bazy danych
def save_anomaly(anomaly_data):
    if not anomaly_data:
        return None
    session = SessionLocal()
    try:
        from database.tables import Anomaly
        anomaly = Anomaly(**anomaly_data)
        session.add(anomaly)
        session.commit()
        logger.info(f"Anomaly saved: score={anomaly_data['anomaly_score']}, severity={anomaly_data['severity_level']}")
        return anomaly.id
    except Exception as e:
        session.rollback()
        logger.error(f"Error saving anomaly: {e}")
        return None
    finally:
        session.close()


#zapisanie alertu do bazy danych

def save_alert(anomaly_id):
    if not anomaly_id:
        return
    session = SessionLocal()
    try:
        from database.tables import Alert
        alert = Alert(anomaly_id=anomaly_id, status="new")
        session.add(alert)
        session.commit()
        logger.info(f"Alert saved for anomaly ID: {anomaly_id}")
    except Exception as e:
        session.rollback()
        logger.error(f"Error saving alert: {e}")
    finally:
        session.close()


#wyznaczanie poziomu istotności na podstawie anomaly score

def determine_severity(score):

    #im bardziej ujemny score, tym większa anomalia
    
    if score < -0.5:
        return "high"
    elif score < -0.2:
        return "medium"
    else:
        return "low"