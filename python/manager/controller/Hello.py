from flask_restful import Resource


class HelloCtrl(Resource):
    def get(self):
        return {'hello': 'world'}

