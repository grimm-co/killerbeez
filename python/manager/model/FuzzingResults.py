from app import app
from datetime import *

db = app.config['db']

'''
For simplicity I am just using one simple model for each crash and not using the previous db schema. We may want to move
the crash system to a bugzilla friendly format. Based on the decision on the design of crash analysis (clientside or serverside)
, improvement could be made.
'''


class results(db.Model):
    result_id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('fuzz_jobs.job_id'), nullable=False)
    repro_file = db.Column(db.String, nullable=False)
    result_type = db.Column(db.String) # 'hang' or 'crash'

    def __init__(self, job_id, repro, type='crash'):
        self.job_id = job_id
        self.repro_file = repro
        self.result_type = type

    def as_dict(self):
        return {c.name: str(getattr(self, c.name)) for c in self.__table__.columns}
