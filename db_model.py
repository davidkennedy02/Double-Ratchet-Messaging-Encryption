from __future__ import annotations
from typing import List 
from sqlalchemy import create_engine, Column, Table, Integer, String, DateTime, ForeignKey, select, text, URL
from sqlalchemy.orm import  Mapped, mapped_column, relationship, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# host=dk94.teaching.cs.st-andrews.ac.uk
# user=dk94
# password=tk3V!shm4sC207


connection_url = URL.create(
    "mysql+mysqlconnector",
    username="dk94",
    password="tk3V!shm4sC207",
    host="dk94.teaching.cs.st-andrews.ac.uk",
    database="dk94_cs4203",
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
    cert_tls = Column(String(5000), unique=True, nullable=False)
    identity_key = Column(String(5000), unique=True, nullable=False)
    signed_pre_key = Column(String(5000), unique=True, nullable=False)
    signature = Column(String(5000), unique=True, nullable=False)


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


Base.metadata.create_all(engine)

