from . import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password = db.Column(db.String(256))

    def __repr__(self):
        return f'<User {self.username}>'
    
class URL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(256), nullable=False, index=True)
    status = db.Column(db.Enum('online', 'offline', name='status_enum'), nullable=False)
    monitoring_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

    def __repr__(self):
        return f'<URL {self.url}>'
    
class CVE(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cve = db.Column(db.String(64), index=True, unique=True, nullable=True)
    cwe = db.Column(db.Text)
    description = db.Column(db.Text)
    vectorString = db.Column(db.Text)
    baseScore = db.Column(db.Float)
    baseSeverity = db.Column(db.String(64))
    exploitabilityScore = db.Column(db.Float)
    impactScore = db.Column(db.Float)
    nucleiResult = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    
    def __repr__(self):
        return f'<CVE {self.cve}>'

class Tech(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tech = db.Column(db.String(128), nullable=False)
    version = db.Column(db.String(64), nullable=True)

    def __repr__(self):
        return f'<Tech {self.tech} {self.version}>'

class Tech_CVE(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tech_id = db.Column(db.Integer, db.ForeignKey('tech.id'), nullable=False)
    cve_id = db.Column(db.Integer, db.ForeignKey('cve.id'), nullable=False)
    detected_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    tech = db.relationship('Tech', backref=db.backref('cve_associations', lazy=True))
    cve = db.relationship('CVE', backref=db.backref('tech_associations', lazy=True))

class URL_Tech(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url_id = db.Column(db.Integer, db.ForeignKey('url.id'), nullable=False)
    tech_id = db.Column(db.Integer, db.ForeignKey('tech.id'), nullable=False)
    detected_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    url = db.relationship('URL', backref=db.backref('tech_associations', lazy=True))
    tech = db.relationship('Tech', backref=db.backref('url_associations', lazy=True))
    



