from database.connection import engine, Base
from database.tables import *

#tworzenie w bazie wszystkich tabeli opisanych w pliku tables.py

Base.metadata.create_all(engine)

print("All tables have been created")