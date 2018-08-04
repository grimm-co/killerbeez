from app import app

db = app.config['db']

class job_inputs(db.Model):
    job_id = db.Column(db.Integer, db.ForeignKey('fuzz_jobs.job_id'), nullable=False, primary_key=True)
    job = db.relationship('fuzz_jobs', back_populates='inputs')
    input_id = db.Column(db.Integer, db.ForeignKey('inputs.input_id'), nullable=False, primary_key=True)
    input = db.relationship('inputs')

    def as_dict(self):
        return {c.name: str(getattr(self, c.name)) for c in self.__table__.columns}
