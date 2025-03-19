import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'mysql+mysqlconnector://root:admin@localhost/mydb'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    TEMPLATE_AUTO_RELOAD = True
    
    # Set up mail server
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = '587'
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = 'vtscanningtool@gmail.com'
    MAIL_PASSWORD = 'zflo koln cwjf xjoc'
    MAIL_DEFAULT_SENDER = ('Công cụ quét bảo mật', 'vtscanningtool@gmail.com')