#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Aug 22 17:53:32 2017

@author: Tripp
"""

from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from sqlalchemy import create_engine
import datetime
from sqlalchemy.types import Boolean, DateTime
from passlib.apps import custom_app_context as pw_context
from flask import jsonify
import json

Base = declarative_base()


class User(Base):

    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    password = Column(String(80))
    email = Column(String(80), nullable=False, index=True)

    def hash_password(self, password):
        self.password = pw_context.encrypt(password)

    def verify_password(self, password):
        return pw_context.verify(password, self.password)

    @property
    def serialize(self):
        return {
                'email': self.email
                }


class Make(Base):

    __tablename__ = 'make'

    id = Column(Integer, primary_key=True)
    name = Column(String(250))

    @property
    def serialize(self):
        return {
                'make': self.name,
                'models': [model.serialize for model in self.model]
                }


class Model(Base):

    __tablename__ = 'model'

    id = Column(Integer, primary_key=True)
    created = Column(DateTime, default=datetime.datetime.utcnow)
    name = Column(String(50))
    year = Column(Integer)
    trim = Column(String(20))
    color = Column(String(20))
    condition = Column(String(20))
    mileage = Column(Integer)
    accident = Column(Boolean)
    make_id = Column(Integer, ForeignKey('make.id'))
    make = relationship(Make, backref=backref("model", cascade="all,delete"))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User, backref=backref("model", cascade="all,delete"))
    description = Column(String(500))

    @property
    def serialize(self):
        return {
                'model': self.name,
                'year': self.year,
                'trim': self.trim,
                'color': self.color,
                'mileage': self.mileage,
                'accident': 'Has had accident'
                if self.accident else 'No accident history',
                'condition': self.condition
                }


class Photo(Base):

    __tablename__ = 'photo'

    path = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    description = Column(String(200))
    model_id = Column(Integer, ForeignKey('model.id'))
    model = relationship(Model, backref=backref("photo", cascade="all,delete"))
    
dbpassword = json.loads(open('client_secrets.json', 'r').
                        read())['database']['password']

print(dbpassword)

engine = create_engine('postgresql+psycopg2://ubuntu:' + dbpassword + '@localhost/catalog.db')
Base.metadata.create_all(engine)
