from flask_restful import Resource, reqparse, fields, marshal_with, abort
import sys

from model.FuzzingJob import fuzz_jobs
from model.Config import FuzzingConfig

from app import app

db = app.config['db']

config_fields = {
    'name': fields.String,
    'target_id': fields.Integer,
    'job_id': fields.Integer,
    'value': fields.String,
}

class ConfigCtrl(Resource):
    def create(self, target_id, job_id, name, value):
        config = FuzzingConfig(name, value, target=target_id, job=job_id)
        db.session.add(config)
        db.session.commit()
        return config

    def read(self, id):
        # TODO allow for querying of configs
        pass

    @marshal_with(config_fields)
    def post(self):
        err = list()
        target_id = None
        job_id = None
        parser = reqparse.RequestParser()
        parser.add_argument('job_id', type=int)
        parser.add_argument('target_id', type=int)
        parser.add_argument('name', type=str)
        parser.add_argument('value', type=str)
        args = parser.parse_args()
        if args.name is None or args.name == "":
            err.append("no configuration name supplied; it is required")
        if args.value is None or args.value == "":
            err.append("no configuration value supplied; it is required")
        # Determine if this is for a target or a job
        if args.target_id is not None and args.target_id != 0:
            target_id = args.target_id
        if args.job_id is not None and args.job_id != 0:
            job_id = args.job_id
        if target_id is not None and job_id is not None:
            err.append("target_id and job_id are mutually exclusive")
        if target_id is None and job_id is None:
            err.append('must supply either a target_id or a job_id')
        if len(err) != 0:
            abort(400, err=', '.join(err))
        # Ok, make one.
        if target_id is None:
            target_id = 0
        if job_id is None:
            job_id = 0
        return self.create(target_id, job_id, args.name, args.value)

    @marshal_with(config_fields)
    def get(self):
        target_id = None
        job_id = None
        parser = reqparse.RequestParser()
        parser.add_argument('job_id', type=int)
        parser.add_argument('target_id', type=int)
        parser.add_argument('name', type=str)
        args = parser.parse_args()
        # Determine if this is for a target or a job
        if args.target_id is not None and args.target_id != 0:
            target_id = args.target_id
        if args.job_id is not None and args.job_id != 0:
            job_id = args.job_id
        if target_id is not None and job_id is not None:
            abort(400, err='target_id and job_id are mutually exclusive')

        query = db.session.query(FuzzingConfig)
        if args.name is not None:
            query = query.filter_by(name=args.name)
        if job_id is not None:
            query = query.filter_by(job_id=job_id)
        if target_id is not None:
            query = query.filter_by(target_id=target_id)
        configs = query.all()
        #configs = [config.as_dict() for config in configs]
        return configs
