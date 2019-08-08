from app import app

from sqlalchemy.orm.collections import attribute_mapped_collection

db = app.config['db']

class targets(db.Model):
    target_id = db.Column(db.Integer, primary_key=True, nullable=False)
    platform = db.Column(db.String(), nullable=False)
    target_executable = db.Column(db.String(), nullable=False)

    configs = db.relationship('FuzzingConfig', back_populates='target',
                              collection_class=attribute_mapped_collection('name'))

    def __init__(self, platform, exe):
        self.platform = platform
        self.target_executable = exe

    def __str__(self):
        return '{}_{}'.format(self.target_executable, self.platform)

    def as_dict(self):
        return {c.name: str(getattr(self, c.name)) for c in self.__table__.columns}
