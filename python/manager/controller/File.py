import base64
import logging
import os.path
import sys
import urllib.parse

from flask import request, make_response, json
from flask_restful import Resource, reqparse, fields, marshal_with, abort

from app import app
from lib import boinc
from lib import errors
from model.FuzzingJob import fuzz_jobs

db = app.config['db']
logger = logging.getLogger(__name__)

file_fields = {
    'filename': fields.String(),
    # TODO: this should be the whole URL
    'path': fields.String(),
    'hash': fields.String(),
}

class FileCtrl(Resource):
    def create(self, contents):
        try:
            filename = boinc.filename_to_download_path(
                boinc.stage_file('input', contents))
        except errors.Error:
            logger.exception('unable to stage file')
            abort(400, err='unable to stage file')

        return {'filename': os.path.basename(filename), 'path': filename,
                'hash': filename.split('_')[-1]}, 200

    def _get_hash(self, content):
        return hashlib.md5(content).hexdigest()

    @marshal_with(file_fields)
    def search(self, hash=None, content=None):
        if hash is not None:
            filename = boinc.get_filename('input', hash)
        elif content is not None:
            hash = self._get_hash(content)
            filename = boinc.get_filename('input', hash)
        else:
            abort(400, err='no filtering criteria provided')

        if os.path.exists(filename):
            with open(filename, 'rb') as input_file:
                if content is not None and input_file.read() != content:
                    abort(400, err='file does not match specified contents')
            return [{'filename': os.path.basename(filename),
                     'path': boinc.filename_to_download_path(filename),
                     'hash': hash}]
        else:
            # Nothing valid found
            abort(404, err='not found')

    def _content_decode(self, args):
        if args.encoding == 'url':
            content = urllib.parse.unquote_to_bytes(args.content)
        elif args.encoding == 'base64':
            try:
                content = base64.b64decode(args.content)
            except binascii.Error:
                abort(400, err='Invalid base64 encoding')
        else:
            abort(400, err='Invalid encoding (accepted values are "url" and "base64")')

        if args.hash:
            hash = self._get_hash(content)
            if hash != args.hash:
                abort(400, err='Content does not match provided hash')

        return content

    @marshal_with(file_fields)
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('encoding', type=str, default='url')
        parser.add_argument('content', type=str, required=True)
        parser.add_argument('hash', type=str)
        args = parser.parse_args()

        content = self._content_decode(args)
        return self.create(content)

    def get(self):
        """
        Query the file DB for a matching file
        :return: Dict containing the info on the file and 200, if present, else error message and 400 or 404
        """
        parser = reqparse.RequestParser()
        parser.add_argument('encoding', type=str, default='url')
        parser.add_argument('content', type=str)
        parser.add_argument('hash', type=str)
        args = parser.parse_args()

        content = self._content_decode(args) if args.content else None
        return self.search(args.hash, content)
