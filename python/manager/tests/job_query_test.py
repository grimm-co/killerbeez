from flask_sqlalchemy import sqlalchemy
import os, sys, random

# Find the directory with our source in it and add it to the lookup path
if "app" in os.listdir():
    sys.path.insert(0, os.path.abspath('.'))
else:
    sys.path.insert(0, os.path.abspath('..'))

from app import app
from model.FuzzingTarget import targets
from model.FuzzingJob import fuzz_jobs
from model.job_inputs import job_inputs
from model.FuzzingInputs import inputs
#from model.tracer_info import tracer_info
#from controller.Minimize import minimize

db = app.config['db']

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description="Test things")
    parser.add_argument("-setup", action="store_true", help="Setup the database")
    parser.add_argument("-clear", action="store_true", help="Clear the database")
    parser.add_argument("-target_id", type=int, default=1, help="target id to use")
    args = parser.parse_args()

    if args.clear:
        db.drop_all()
        db.create_all()
        db.session.commit()

    #if args.setup:
    if True:
        # Add some fake data to test against
        #base = (args.target_id << 8)

        # Add a few targets
        db.session.add(targets(None, "x86", "Windows 10", "test2.exe"))
        db.session.add(targets(None, "x86", "Windows 8", "test1.exe"))
        db.session.add(targets(None, "x86_64", "Windows 10", "test2.exe"))
        db.session.add(fuzz_jobs("fuzz", 1, status='assigned'))
        db.session.add(fuzz_jobs("fuzz", 2))
        db.session.add(fuzz_jobs("fuzz", 2))
        db.session.add(fuzz_jobs("fuzz", 1))
        db.session.add(fuzz_jobs("fuzz", 1))
        db.session.add(fuzz_jobs("fuzz", 3))
        db.session.add(inputs("AAAAAAAA"))
        db.session.add(inputs("BBBBBBBB"))
        db.session.add(job_inputs(4, 1))
        db.session.add(job_inputs(4, 2))
        #db.session.add(job_inputs(5, 1))
        db.session.add(job_inputs(5, 2))
        db.session.add(job_inputs(1, 1))
        #db.session.add(job_inputs(1, 2))
        db.session.commit()
        # Can we get a result back out?
        tars = db.session.query(targets).all()
        print("all targets:{}".format(len(tars)))
        tars = db.session.query(targets).filter_by(architecture="x86").all()
        print("x86 targets:{}".format(len(tars)))
        tars = db.session.query(targets).filter_by(target_executable="test2.exe").all()
        print("test2 tars :{}".format(len(tars)))
        # Get all jobs associated with x86 architecture and windows 10 that are unassigned
        query = db.session.query(fuzz_jobs) \
                .filter_by(status='unassigned') \
                .join(targets, targets.target_id == fuzz_jobs.target_id) \
                .filter_by(architecture="x86", os="Windows 10")
        jobs = query.all()
        print(len(jobs))
        job = random.choice(jobs)
        print(job.job_id)
        #inputs = db.session.query(job_inputs.input_id).filter_by(job_id=job.job_id).all()
        #inputs = db.session.query(job_inputs.input_id, inputs) \\
        inputs = db.session.query(job_inputs.input_id, inputs) \
                 .filter_by(job_id=job.job_id) \
                 .join(inputs, job_inputs.input_id == inputs.input_id).all()
        if len(inputs):
            inputs = [input[1].as_dict() for input in inputs]
        else:
            print("No inputs, we can't do anything")
        print(inputs)
    sys.exit()