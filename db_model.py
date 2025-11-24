from sqlalchemy import create_engine, Column, Table, Integer, String, ForeignKey, URL
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
import os
from dotenv import load_dotenv

load_dotenv()

connection_url = URL.create(
    "mysql+mysqlconnector",
    username=os.getenv("DB_USER", "dk94"),
    password=os.getenv("DB_PASSWORD", "tk3V!shm4sC207"),
    host=os.getenv("DB_HOST", "dk94.teaching.cs.st-andrews.ac.uk"),
    database=os.getenv("DB_NAME", "dk94_cs4203"),
)

engine = create_engine(connection_url)

Base = declarative_base()

group_user = Table('group_user', Base.metadata, Column('user_id', Integer, ForeignKey('users.id')), Column('group_id', Integer, ForeignKey('groups.id')))


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False)
    password = Column(String(250), unique=False, nullable=False)
    salt = Column(String(250), unique=True, nullable=False)
    cert_tls = Column(String(3000), unique=False, nullable=False)
    identity_key = Column(String(750), unique=True, nullable=False)
    signed_pre_key = Column(String(750), unique=True, nullable=False)
    signature = Column(String(750), unique=True, nullable=False)


class Group(Base):
    __tablename__ = 'groups'

    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False)
    users = relationship('User', secondary=group_user, backref='groups')

    def __repr__(self):
        return f'<Group "{self.name}">'
    

class Message(Base):
    '''
    Type - Group - Address - Content 
    //
    Holds all messages sent client-client. 
    Messages are deleted once accessed by client. 
    Client-side fan-out.
    '''

    __tablename__ = 'messages'

    id = Column(Integer, primary_key=True)
    type = Column(String(100), nullable=True)
    group = Column(String(100), nullable=True)
    address = Column(String(100), ForeignKey('users.username'), nullable=False)
    content = Column(String(10000), nullable=False)