from flask_sqlalchemy import sqlalchemy
import os, sys

# Find the directory with our source in it and add it to the lookup path
if "app" in os.listdir():
    sys.path.insert(0, os.path.abspath('.'))
else:
    sys.path.insert(0, os.path.abspath('..'))

from app import app 
from model.FuzzingTarget import targets
from model.FuzzingJob import fuzz_jobs
from model.FuzzingInputs import inputs, inputs_hash
from model.tracer_info import tracer_info
from controller.Minimize import minimize

db = app.config['db']

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description="Test things")
    parser.add_argument("-setup", action="store_true", help="Setup the database")
    parser.add_argument("-clear", action="store_true", help="Clear the database")
    parser.add_argument("-target_id", type=int, default=1, help="target id to use")
    parser.add_argument("-num_files_per_edge", type=int, default=1, help="The number of files per edge to include in the working set")
    args = parser.parse_args()

    if args.clear:
        db.drop_all()
        db.create_all()
        db.session.commit()

    if args.setup:
        # Add some fake data to test against
        base = (args.target_id << 8)
        tests_info = [
            {"job_id": base + 1, "input_id" : base + 1, "data": "AAAA",  "edges" : [(1, 2), (3, 4)]},
            {"job_id": base + 2, "input_id" : base + 2, "data": "ABCD",  "edges" : [(1, 2), (5, 6)]},
            {"job_id": base + 3, "input_id" : base + 3, "data": "XXXXXXX", "edges" : [(1, 2), (3, 4), (5,6)]},
            {"job_id": base + 4, "input_id" : base + 4, "data": "XXXXXX", "edges" : [(1, 2), (3, 4), (5,6)]},
            {"job_id": base + 5, "input_id" : base + 5, "data": "XXXXX", "edges" : [(1, 2), (3, 4), (5,6)]},
            {"job_id": base + 6, "input_id" : base + 6, "data": "ZZZZZZZZZ", "edges" : [(7,8)]},
        ]

        db.session.add(targets(args.target_id, "x86", "Windows10", "test2.exe"))
        for test_info in tests_info:
            db.session.add(fuzz_jobs("user", args.target_id, None, None, None, None, "finished", test_info["job_id"]))
            
            hash = inputs_hash(test_info["data"])
            input = inputs.query.filter_by(hash = hash).all() 
            if len(input) == 0:
                db.session.add(inputs(test_info["data"], test_info["job_id"], input_id = test_info["input_id"]))
            else:
                test_info["input_id"] = input[0].input_id

            for edge in test_info["edges"]:
                db.session.add(tracer_info(args.target_id, test_info["input_id"], edge[0], edge[1]))
        db.session.commit()

    files = minimize(args.target_id, args.num_files_per_edge)
    print(files)