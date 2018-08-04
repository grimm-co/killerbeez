from flask_restful import Resource, reqparse
from app import app
from app import logFile

db = app.config['db']


class LogCtrl(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('message', required=True, location='json')
        args = parser.parse_args()
        with open(logFile, 'a') as f:
            f.write(args['message'])

        return { "msg" : "log created successfully" }, 201

    def get(self):
        try:
            log = open(logFile, 'r').read()
        except:
            return {"err": "not found"}, 404

        return { "log" : log }, 200