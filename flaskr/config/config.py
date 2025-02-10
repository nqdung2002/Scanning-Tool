import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'mysql+mysqlconnector://root:thuy123@localhost/mydb'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    TEMPLATE_AUTO_RELOAD = True