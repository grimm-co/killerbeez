from app import app

db = app.config['db']

class input_sources(db.Model):
    """
    This table indicates the source of a given input (i.e., what job created it).
    This is used to keep a one-to-many lookup of the multiple jobs that may have created a file without
    requiring multiple (larger) entries in the inputs table.
    """
    job_id = db.Column(db.Integer, db.ForeignKey('fuzz_jobs.job_id'), nullable=False, primary_key=True)
    job = db.relationship('fuzz_jobs')
    input_id = db.Column(db.Integer, db.ForeignKey('inputs.input_id'), nullable=False, primary_key=True)
    input = db.relationship('inputs', back_populates='source_jobs')

    def as_dict(self):
        return {c.name: str(getattr(self, c.name)) for c in self.__table__.columns}
