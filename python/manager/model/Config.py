from app import app
from model.FuzzingTarget import targets
from model.FuzzingJob import fuzz_jobs
db = app.config['db']

class FuzzingConfig(db.Model):
    config_id = db.Column(db.Integer, primary_key=True, nullable=False)
    target_id = db.Column(db.Integer, db.ForeignKey('targets.target_id'))
    job_id = db.Column(db.Integer, db.ForeignKey('fuzz_jobs.job_id'))
    name = db.Column(db.String(), nullable=False,)
    value = db.Column(db.String(), nullable=False)

    target = db.relationship('targets', back_populates='configs')
    job = db.relationship('fuzz_jobs', back_populates='configs')

    def __init__(self, config_name, config_value, config_id=None, target=0, job=0):
        # TODO: sanity check that target and job aren't both 0?
        # TODO: The check is already done in the post, but should san check it here anyway.
        self.config_id = config_id
        self.target_id = target
        self.job_id = job
        self.name = config_name
        self.value = config_value

    def as_dict(self):
        out = {c.name: str(getattr(self, c.name)) for c in self.__table__.columns}
        return out
