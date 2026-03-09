from database.connection import engine, Base
from database.tables import *

Base.metadata.create_all(engine)
print("All tables has been created")
