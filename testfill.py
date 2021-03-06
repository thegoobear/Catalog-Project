#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Aug 25 22:45:18 2017

@author: Tripp
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Make, Photo, Model, User

if __name__ == '__main__':

    engine = create_engine('postgresql+psycopg2://ubuntu@localhost/catalog')
    Base.metadata.bind = engine
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    Bob = User(email='test@test.com')
    Ford = Make(name='Ford')
    Chevrolet = Make(name='Chevrolet')
    Jeep = Make(name='Jeep')
    Dodge = Make(name='Dodge')
    Ferarri = Make(name='Ferarri')
    Lincoln = Make(name='Lincoln')
    Focus = Model(
            make=Ford, name='Focus', year=2001, trim='LX', color='blue',
            mileage=35609, accident=False, description='Test', user=Bob)
    Bronco = Model(make=Ford, name='Bronco', year=1988, trim='Standard',
                   color='white', mileage=167609, accident=True,
                   description='Test', user=Bob)
    Colorado = Model(
            make=Chevrolet, name='Colorado', year=1988, trim='Super-Duty',
            color='red', mileage=187609, accident=True,
            description='Test', user=Bob)

    FocusPhoto = Photo(
            model=Focus, path='focus.jpg', description='A Ford Focus')

    NoPhoto = Photo(path='nophoto.png', model=Bronco)
    NoPhoto2 = Photo(path='nophoto.png', model=Colorado)

    session.add(NoPhoto2)
    session.add(NoPhoto)
    session.add(Ford)
    session.add(Chevrolet)
    session.add(Jeep)
    session.add(Dodge)
    session.add(Ferarri)
    session.add(Lincoln)
    session.add(Focus)
    session.add(Bronco)
    session.add(Colorado)
    session.commit()
