import time, traceback, os, uuid

from flask import Flask, jsonify, request, json
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api

import app.config as config_file
from app.encoder import JSONEncoder

app = Flask(__name__, static_folder='static', static_url_path='')


"""
    Setup DB Models
"""
app.config['SQLALCHEMY_DATABASE_URI'] = config_file.DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['RESTFUL_JSON'] = {'cls': JSONEncoder}
app.config['ERROR_404_HELP'] = False
app.config['db'] = db = SQLAlchemy(app)

# TODO verification of version via metadata table.


"""
    Setup Routes
"""
from controller.Hello import HelloCtrl
from controller.Minimize import MinimizeCtrl
# TODO The controllers below here still need to be finished
from controller.File import FileCtrl
from controller.Job import JobCtrl
from controller.Target import TargetCtrl
from controller.Config import ConfigCtrl
from controller.Results import ResultsCtrl

api = Api(app)
api.add_resource(HelloCtrl, '/')
api.add_resource(MinimizeCtrl, '/api/minimize')
api.add_resource(FileCtrl, '/api/file', methods=['GET', 'POST'])

api.add_resource(JobCtrl, '/api/job', methods=['GET', 'POST'])
api.add_resource(JobCtrl, '/api/job/<int:id>', methods=['GET'], endpoint='jobctrl_id')
api.add_resource(JobCtrl, '/api/boinc_job/<int:boinc_id>', methods=['GET'], endpoint='jobctrl_boincid')
api.add_resource(ResultsCtrl, '/api/results', methods=['GET'])
api.add_resource(ResultsCtrl, '/api/job/<int:job_id>/results', endpoint='resultsctrl_job')
api.add_resource(ResultsCtrl, '/api/boinc_job/<int:boinc_id>/results', endpoint='resultsctrl_boincjob')

api.add_resource(TargetCtrl, '/api/target', methods=['GET', 'POST'])
api.add_resource(TargetCtrl, '/api/target/<int:id>', methods=['GET', 'PUT', 'DELETE'], endpoint='targetctrl_id')
# api.add_resource(CrashBucketCtrl, '/api/bucket', '/api/bucket/<string:id>')

api.add_resource(ConfigCtrl, '/api/config')
#api.add_resource(UpdateCtrl, '/api/update/<string:hash>')

