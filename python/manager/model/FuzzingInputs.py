from app import app
import hashlib

from sqlalchemy.ext.hybrid import hybrid_property

db = app.config['db']

def inputs_hash(contents):
    hash = hashlib.sha256()
    if type(contents) == str:
        contents = bytes(contents, "ascii")
    hash.update(contents)
    return hash.hexdigest()

class inputs(db.Model):
    input_id = db.Column(db.Integer, primary_key=True)
    _hash = db.Column('hash', db.String(), unique=True)
    _contents = db.Column('contents', db.LargeBinary())
    compressed = db.Column(db.Boolean)
    source_jobs = db.relationship('input_sources', back_populates='input')

    def __init__(self, contents=None, input_id=None, compressed=False):
        self.input_id = input_id
        self.compressed = compressed

        if type(contents) == str: # Python3 compat
            contents = bytes(contents, "ascii")
        self.contents = contents

    @hybrid_property
    def contents(self):
        return self._contents

    @contents.setter
    def contents(self, contents):
        if contents:
            self._contents = contents
            self._hash = inputs_hash(contents)

    @hybrid_property
    def hash(self):
        return self._hash

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns if c.name != 'contents'}
