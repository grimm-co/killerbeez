from flask_restful import Resource
from datetime import datetime
#from model.FuzzingJobState import FuzzingJobState
from model.FuzzingJob import fuzz_jobs
#from model.FuzzingHost import FuzzingHost
from model.FuzzingCrash import results

class StatusCtrl(Resource):
    def get(self):
        status_active = FuzzingJobState.query.filter_by(name='Active').first()
        status_completed = FuzzingJobState.query.filter_by(name='Completed').first()
        status_queued = FuzzingJobState.query.filter_by(name='Queued').first()

        total_job_count = FuzzingJob.query.count()
        active_job_count = FuzzingJob.query.filter_by(state_id=status_active.id).count()
        completed_job_count = FuzzingJob.query.filter_by(state_id=status_completed.id).count()
        queued_job_count = FuzzingJob.query.filter_by(state_id=status_queued.id).count()
        crash_count = FuzzingCrash.query.count()
        node_count = FuzzingHost.query.count()
        return {
            'total_job_count': total_job_count,
            'active_job_count': active_job_count,
            'completed_job_count': completed_job_count,
            'queued_job_count': queued_job_count,
            'crash_count': crash_count,
            'node_count': node_count,
            'serverTime' : str(datetime.now())
        }, 200
