from sqlalchemy import Column, Integer, String, JSON
from ..database.db import Base

class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    endpoint_id = Column(String)
    event_type = Column(String)
    timestamp = Column(String)
    data = Column(JSON)
