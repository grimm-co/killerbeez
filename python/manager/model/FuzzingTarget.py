from app import app

from sqlalchemy.orm.collections import attribute_mapped_collection

db = app.config['db']

'''
CREATE TABLE targets (
    target_id integer NOT NULL,
    architecture text NOT NULL,
    os text NOT NULL,
    target_executable text NOT NULL
);
'''

class targets(db.Model):
    target_id = db.Column(db.Integer, primary_key=True, nullable=False)
    architecture = db.Column(db.String(), nullable=False)
    os = db.Column(db.String(), nullable=False)
    target_executable = db.Column(db.String(), nullable=False)

    configs = db.relationship('FuzzingConfig', back_populates='target',
                              collection_class=attribute_mapped_collection('name'))

    def __init__(self, architecture, os, exe):
        self.architecture = architecture
        self.os = os
        self.target_executable = exe

    def as_dict(self):
        return {c.name: str(getattr(self, c.name)) for c in self.__table__.columns}
