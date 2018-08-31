from flask_restful import Resource, reqparse, fields, marshal_with, abort
from model.FuzzingJob import fuzz_jobs
from model.FuzzingResults import results
from app import app


db = app.config['db']

result_fields = {
    'result_id': fields.Integer(),
    'job_id': fields.Integer(),
    'repro_file': fields.String(),
    'result_type': fields.String(),
}

class ResultsCtrl(Resource):
    def create(self, data, job_id=None, boinc_id=None):
        if job_id is not None:
            job = fuzz_jobs.query.get(job_id)
            if job is None:
                abort(404, err="job not found")
        elif boinc_id is not None:
            job = fuzz_jobs.query.filter_by(boinc_id=boinc_id).first()
            if job is None:
                abort(404, err="boinc_job not found")
            job_id = job.job_id

        try:
            result = results(job_id, data['repro_file'], type=data['result_type'])
            db.session.add(result)
            db.session.commit()
        except Exception as e:
            abort(400, err="invalid request")

        return result, 201

    # TODO if needed
    def read(self, job_id=None):
        query = results.query
        if job_id:
            query = query.filter_by(job_id=job_id)
        job_results = query.all()
        # TODO: maybe don't error depending on job status
        if not job_results:
            abort(404, err="not found")
        return job_results, 200

    # TODO if needed
    def update(self, id, data):
        crash = FuzzingCrash.query.filter_by(id=id).first()
        if crash is None:
            abort(404, err="not found")


        job = FuzzingJob.query.filter_by(id=data['job_id']).first()
        if job is not None:
            crash.job = job

        if data['repro_file'] is not None:
            crash.repro_file= data['dump_file']

        if data['dump_file'] is not None:
            crash.dump_file = data['dump_file']

        if data['dbg_file'] is not None:
            crash.dbg_file = data['dbg_file']
        try:
            db.session.commit()
        except Exception as e:
            abort(400, err="invalid request")

        return crash.as_dict(), 201


    # TODO if needed
    def delete(self, id):
        crash = FuzzingCrash.query.filter_by(id=id).first()
        if crash is None:
            abort(404, err="not found")
        try:
            db.session.delete(crash)
            db.session.commit()
        except Exception as e:
            abort(400, err="invalid request")

        return {"msg" : "record removed successfully"}, 201

    def list(self, offset=None, limit=None, job_id=None, boinc_id=None, repro_file=None):
        query = results.query
        # results filters
        if job_id:
            query = query.filter_by(job_id=job_id)
        if repro_file:
            query = query.filter_by(repro_file=repro_file)

        # filters requiring join with fuzz_jobs
        if boinc_id:
            query = query.join(fuzz_jobs).filter(fuzz_jobs.boinc_id == boinc_id)

        if offset is None:
            offset = 0
        if limit is None:
            limit = 20
        crashes = query.offset(offset).limit(limit).all()
        return crashes, 200

    @marshal_with(result_fields)
    def get(self, job_id=None, boinc_id=None):
        parser = reqparse.RequestParser()
        parser.add_argument('offset', type=int)
        parser.add_argument('limit', type=int)
        parser.add_argument('repro_file', type=str)
        args = parser.parse_args()
        return self.list(args['offset'], args['limit'], job_id, boinc_id, args['repro_file'])

    @marshal_with(result_fields)
    def post(self, job_id=None, boinc_id=None):
        parser = reqparse.RequestParser()
        parser.add_argument('repro_file', required=True, location='json')
        parser.add_argument('result_type', required=True, location='json')
        parser.add_argument('parent_file', location='json')
        return self.create(parser.parse_args(), job_id, boinc_id)
