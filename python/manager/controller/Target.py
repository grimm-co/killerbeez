import logging

from flask_restful import Resource, reqparse, fields, marshal_with, abort
from model.FuzzingTarget import targets
#from model.FuzzingArch import FuzzingArch
#from model.FuzzingPlatform import FuzzingPlatform
#from model.FuzzingConfig import FuzzingConfig
from app import app


logger = logging.getLogger(__name__)
db = app.config['db']

target_fields = {
    'id': fields.Integer(attribute='target_id'),
    'platform': fields.String,
    'target_executable': fields.String,
}


class TargetCtrl(Resource):
    def create(self, data):
        try:
            target = targets(data['platform'], data['target_executable'])
            db.session.add(target)
            db.session.commit()
        except Exception:
            logger.exception('Error creating target')
            abort(400, err="invalid request")

        return target, 201

    def read(self, id):
        target = targets.query.get(id)
        if target is None:
            abort(404, err="not found")
        return target

    def update(self, id, data):
        target = targets.query.get(id)
        if target is None:
            abort(404, err="not found")

        target.platform = data['platform']
        target.target_executable = data['target_executable']
        try:
            db.session.commit()
        except Exception as e:
            abort(400, err="invalid request")

        return target, 200

    def list(self, offset=0, limit=10000):
        targets_found = targets.query.offset(offset).limit(limit).all()
        return targets_found

    @marshal_with(target_fields)
    def get(self, id=None):
        parser = reqparse.RequestParser()
        parser.add_argument('offset', type=int)
        parser.add_argument('limit', type=int)
        args = parser.parse_args()
        if id is None:
            if args['offset'] is not None and args['limit'] is not None:
                return self.list(args['offset'], args['limit'])
            else:
                return self.list()
        else:
            return self.read(id)

    @marshal_with(target_fields)
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('target_executable', required=True, location='json')
        parser.add_argument('platform', required=True, location='json')
        return self.create(parser.parse_args())

    @marshal_with(target_fields)
    def put(self, id):
        parser = reqparse.RequestParser()
        parser.add_argument('target_executable', required=True, location='json')
        parser.add_argument('platform', required=True, location='json')
        return self.update(id, parser.parse_args())

    def delete(self, id):
        target = targets.query.get(id)
        if target is None:
            return {"err": "not found"}, 404
        try:
            db.session.delete(target)
            db.session.commit()
        except Exception as e:
            return {"err": "invalid request"}, 400

        return {"msg" : "record removed successfully"}, 200
