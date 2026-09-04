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