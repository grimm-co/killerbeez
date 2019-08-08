import collections, operator
from app import app
from flask_restful import Resource, reqparse
from flask import request
from model.tracer_info import tracer_info
from sqlalchemy.sql.expression import func

db = app.config['db']

def minimize(target_id, num_files_per_edge = None):
    if num_files_per_edge == None:
        num_files_per_edge = 1

    # get the data
    query = db.session.query(tracer_info.target_id, tracer_info.from_edge, tracer_info.to_edge, tracer_id.input_file) \
                .filter_by(target_id=target_id)
    data = query.all()

    # Group the data by edge
    edges = collections.defaultdict(list)
    edges_per_input = collections.defaultdict(list)
    for target_id, from_edge, to_edge, input_file in data:
        edges[(int(from_edge), int(to_edge))].append(input_file)
        edges_per_input[input_file].append((from_edge, to_edge))

    edges_by_popularity = sorted(edges, key=lambda k: len(edges[k]), reverse=True)

    already_have = collections.defaultdict(int)
    working_set = []
    for edge in edges_by_popularity:
        if already_have[edge] > num_files_per_edge:
            continue

        files = edges[edge][:(num_files_per_edge - already_have[edge])]
        working_set.extend(files)
        for file in files:
            for edge in edges_per_input[file]:
                already_have[edge] += 1

    return set(working_set)

class MinimizeCtrl(Resource):
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('target_id', type=int, required=True)
        parser.add_argument('num_files_per_edge', type=int)
        args = parser.parse_args()
        return list(minimize(args.target_id, args.num_files_per_edge)) # The return value must be JSON serializable, so turn it back to a list

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Calculate the working set for a given target")
    parser.add_argument("target_id", type=int, help="The target id to get the working set of")
    args = parser.parse_args()

    files = minimize(args.target_id, args.s)
    print("Working set: {}".format(", ".join(files)))
