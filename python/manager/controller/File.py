import sys
import base64
import urllib.parse

from flask import request, make_response, json
from flask_restful import Resource, reqparse, fields, marshal_with, abort

from app import app
from model.FuzzingInputs import inputs, inputs_hash
from model.job_inputs import job_inputs
from model.InputSources import input_sources
from model.FuzzingJob import fuzz_jobs

db = app.config['db']

file_fields = {
    'input_id': fields.Integer(),
    'hash': fields.String(),
    'compressed': fields.Boolean(),
    'source_jobs': fields.List(fields.Integer(attribute='job_id')),
}

class FileCtrl(Resource):
    def _set_source_jobs(self, input, job_ids):
        """Record that the file was discovered by the given list of jobs.

        See if we already knew that, and if not, add it.
        """
        known_ids = set(source.job_id for source in input.source_jobs)
        unknown_ids = set(job_ids) - known_ids
        if unknown_ids:
            for job_id in unknown_ids:
                input.source_jobs.append(input_sources(job_id=job_id))
            db.session.commit()

    def create(self, contents, job_ids):
        hash = inputs_hash(contents)
        input = inputs.query.filter_by(hash=hash).first()

        code = 200
        if input is None:
            input = inputs(contents)
            db.session.add(input)
            db.session.commit()
            code = 201

        if job_ids is not None:
            self._set_source_jobs(input, job_ids)

        return input, code

    def update(self, input_id, job_ids):
        # Determine if an input with the supplied contents already exists
        input = inputs.query.get(input_id)

        if input is None:
            abort(404, err='unknown input_id')

        # input has been added to the inputs db if needed; may still need to make a job or associate with a target
        if job_ids is not None:
            self._set_source_jobs(input, job_ids)

        return input, 200

    def read_content(self, input_id):
        input = inputs.query.get(input_id)
        if input is None or input.contents is None:
            abort(404, err='not found')
        else:
            response = make_response(
                input.contents, 200,
                {'Content-Type': 'application/octet-stream'})
            return response

    @marshal_with(file_fields)
    def search(self, input_id, args):
        # If given a file_id, query by that then verify any other args supplied
        if input_id is not None:
            input = inputs.query.get(input_id)
            if input is not None:
                if args.hash is not None and input.hash != args.hash:
                    abort(400, err='hash mismatch')
                if args.contents is not None and input.contents != args.contents:
                    abort(400, err='contents mismatch')
                return input, 200
        elif args.hash is not None:
            # If no target_id, try hash and verify contents. Return list of file_ids (as this could match multiple)
            input = inputs.query.filter_by(hash=args.hash).first() # There should never be more than one.
            if input is not None:
                if args.contents is not None and input.contents != args.content:
                        abort(400, err='hash does not match contents')
                return input, 200
        elif args.contents is not None:
            # Ok, we only got contents. Query that. Should only get one result, as the hash should be unique
            input = inputs.query.filter_by(contents=args.contents).first()
            if input is not None:
                return input, 200
        else:
            abort(400, err='no filtering criteria provided')
        # Nothing valid found, or no args
        abort(404, err='not found')


    @marshal_with(file_fields)
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('source_jobs', type=int, action='append') # If present, the jobs that created the input
        parser.add_argument('encoding', type=str, default='url')
        parser.add_argument('content', type=str, required=True)
        args = parser.parse_args()

        if args.encoding == 'url':
            content = urllib.parse.unquote_to_bytes(args.content)
        elif args.encoding == 'base64':
            try:
                content = base64.b64decode(args.content)
            except binascii.Error:
                abort(400, err='Invalid base64 encoding')
        else:
            abort(400, err='Invalid encoding (accepted values are "url" and "base64")')

        # TODO: ability to send a hash in the json that it'll check

        return self.create(content, args.source_jobs)

    @marshal_with(file_fields)
    def put(self, input_id):
        parser = reqparse.RequestParser()
        parser.add_argument('source_jobs', type=int, action='append') # If present, the jobs that created the input
        args = parser.parse_args()
        return self.update(input_id, args.source_jobs)

    def get(self, input_id=None):
        """
        Query the file DB for a matching file
        :return: Dict containing the info on the file and 200, if present, else error message and 400 or 404
        """
        if request.endpoint == 'filectrl_content':
            return self.read_content(input_id)
        else:
            parser = reqparse.RequestParser()
            parser.add_argument('contents', type=bytes)
            parser.add_argument('hash', type=bytes)
            args = parser.parse_args()
            return self.search(input_id, args)
