from app import app

db = app.config['db']

class instrumentation_state(db.Model):
    instrumentation_type = db.Column(db.String(), primary_key=True, nullable=False)
    state = db.Column(db.String())
    target_id = db.Column(db.Integer, db.ForeignKey('targets.target_id'), nullable=False, primary_key=True)
    target = db.relationship('targets')

    def __init__(self, instrumentation_type, state, target_id):
        self.target_id = target_id
        self.state = state
        self.instrumentation_type = instrumentation_type

    def as_dict(self):
        return {c.name: str(getattr(self, c.name)) for c in self.__table__.columns}
