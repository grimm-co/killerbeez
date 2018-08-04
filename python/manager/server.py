from app import app
import argparse
import logging

import tests.seeds as seeds
import sys
  
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-seed', help="For debugging. Which test to load seed data for. -listseeds for list.")
    parser.add_argument('-clear', action="store_true", help="For debugging. Clear all data from the database")
    parser.add_argument('-create', action="store_true", help="For debugging. Force creation of databases")
    parser.add_argument('-listseeds', action="store_true", help="List debug seeds that you can choose the exit")
    args = parser.parse_args()

    db = app.config['db']

    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(name)s %(message)s')
    logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)

    if args.listseeds:
        seeds.listseeds()
        sys.exit(0)
    if args.clear:
        db.drop_all()
    #  TODO: Determine if DB already exists and check its schema version
    if args.create:
        db.create_all()
        db.session.commit()
    if args.seed is not None:
        # Seed data into the database for testing.
        if not seeds.seed(db, args.seed):
            print("DEBUG ERROR: Attempting to seed db for invalid test: {}".format(args.seed))

    app.run(host='0.0.0.0')
