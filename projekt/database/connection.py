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