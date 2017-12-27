#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Sep 25 21:33:06 2017

@author: Tripp
"""

from flask_wtf import FlaskForm
from wtforms import TextField, TextAreaField, SubmitField, validators, \
IntegerField, BooleanField, SelectField
from flask_wtf.file import FileField, FileAllowed, FileRequired
from flask_uploads import UploadSet, IMAGES
from database_setup import User
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base

photos = UploadSet('photos', IMAGES)

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind = engine)
session = DBSession()

class PhotoForm(FlaskForm):
    photo = FileField('Photo',
                      [FileAllowed(photos, 'Photos can only be image files'),\
                       FileRequired()])

    description = TextAreaField('Description',
                                [validators.DataRequired\
                                 ('Please enter a description')])

    submit = SubmitField('Upload')

class EditModel(FlaskForm):

    name = TextField('Model',
                    [validators.DataRequired('Please enter the model name')])

    trim = TextField('Body Type',
                    [validators.DataRequired('Please enter body type')])

    mileage = IntegerField('Mileage',
                    [validators.DataRequired('Please enter mileage')],
                    render_kw={'maxlength':6})

    year = IntegerField('Year',
                    [validators.DataRequired('Please the model year')],
                    render_kw={'maxlength':4})

    condition = SelectField('Condition',
                    choices=[('Excellent', 'Excellent'), ('Good', 'Good'),
                             ('Fair', 'Fair'), ('Poor', 'Poor')])

    color = SelectField('Color', choices=[('Black', 'Black'),\
                                          ('White', 'White'), ('Red', 'Red'), 
                                         ('Blue', 'Blue'), ('Other', 'Other')])

    history = BooleanField('Accident History')
    
    description = TextAreaField('Description',
                    [validators.DataRequired('Please enter a description')])

    submit = SubmitField('Save')
    
class NewModel(FlaskForm):
    
    make = TextField('Make',
           [validators.DataRequired('Please enter the manufacturer name')])

    name = TextField('Model',
                    [validators.DataRequired('Please enter the model name')])

    trim = TextField('Body Type',
                    [validators.DataRequired('Please enter body type')])

    mileage = IntegerField('Mileage',
                    [validators.DataRequired('Please enter mileage')],
                    render_kw={'maxlength':6})

    year = IntegerField('Year',
                    [validators.DataRequired('Please enter the model year')],
                    render_kw={'maxlength':4})

    condition = SelectField('Condition',
                    choices=[('Excellent', 'Excellent'), ('Good', 'Good'),
                             ('Fair', 'Fair'), ('Poor', 'Poor')])

    color = SelectField('Color', choices=[('Black', 'Black'),\
                                          ('White', 'White'), ('Red', 'Red'), 
                                         ('Blue', 'Blue'), ('Other', 'Other')])

    history = BooleanField('Accident History')
    
    description = TextAreaField('Description',
                    [validators.DataRequired('Please enter a description')])

    submit = SubmitField('Save')