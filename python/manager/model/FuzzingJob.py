from app import app
from datetime import *

from sqlalchemy.orm.collections import attribute_mapped_collection

db = app.config['db']


class fuzz_jobs(db.Model):
    job_id = db.Column(db.Integer(), primary_key=True, nullable=False)
    boinc_id = db.Column(db.Integer())
    job_type = db.Column(db.String())
    status = db.Column(db.String()) # unassigned, assigned, complete
    mutator_state = db.Column(db.String()) # json of the current state
    mutator = db.Column(db.String())
    instrumentation_type = db.Column(db.String())
    assign_time = db.Column(db.DateTime())
    end_time = db.Column(db.DateTime())
    driver = db.Column(db.String())
    target_id = db.Column(db.Integer(), db.ForeignKey('targets.target_id'))
    seed_file = db.Column(db.String())
    iterations = db.Column(db.Integer())

    target = db.relationship('targets')
    inputs = db.relationship('job_inputs', back_populates='job')
    configs = db.relationship('FuzzingConfig', back_populates='job',
                              collection_class=attribute_mapped_collection('name'))

    def __init__(self,
                 type,
                 target_id,
                 mutator=None, mutator_state=None,
                 instrumentation_type=None,
                 status='unassigned',
                 job_id=None,
                 assign_time=None, driver=None, seed_file=None,
                 iterations=None):
        self.job_id = job_id
        self.job_type = type
        self.target_id = target_id
        self.mutator = mutator
        self.mutator_state = mutator_state
        self.status = status
        self.instrumentation_type = instrumentation_type
        self.assign_time = assign_time
        self.end_time = None
        self.driver = driver
        self.seed_file = seed_file
        self.iterations = iterations

    def lookup_config(self, config_type, config_name):
        """
        Gets options configured for a specific instrumentation, mutator, or
        driver. Looks for job-specific configs first, then falls back to target
        configs.
        :param job: fuzz_jobs, the job the configs should apply to.
        :param config_type: str, the type of object to get configs for, such as
        'instrumentation', 'mutator', or 'driver'.
        :param config_name: str, the name of the mutator, instrumentation, or
        driver to get configs for.
        :return: str if any configuration is stored for the given
        instrumentation/mutator/driver type, otherwise None.
        """
        config_fullname = "{}_opts_{}".format(config_type, config_name)
        # First, check job-specific config
        config = self.configs.get(config_fullname)
        if config is None:
            # If nothing, fall back to target-specific config
            config = self.target.configs.get(config_fullname)
        if config is None:
            return None
        # if we got a result from either of the queries, get the string value
        return config.value

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
