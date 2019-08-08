from app import app

db = app.config['db']

class tracer_info(db.Model):
    target_id = db.Column(db.Integer, db.ForeignKey('targets.target_id'), nullable=False, primary_key=True)
    target = db.relationship('targets')
    input_file = db.Column(db.String, nullable=False, primary_key=True)
    from_edge = db.Column(db.Numeric(asdecimal=True), nullable=False, primary_key=True)
    to_edge = db.Column(db.Numeric(asdecimal=True), nullable=False, primary_key=True)

    def __init__(self, target_id, input_file, from_edge, to_edge):
        self.target_id = target_id
        self.input_file = input_file
        self.from_edge = from_edge
        self.to_edge = to_edge

    def as_dict(self):
        return {c.name: str(getattr(self, c.name)) for c in self.__table__.columns}
