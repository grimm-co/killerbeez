#!/usr/bin/env python

import collections
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

import submit_api


# Set the following to configure your job
AUTHENTICATOR = '6413c786cc8fcc012c9a08d40ac9bb51'
PROJECT = 'http://killerbeez-example.grimm-co.com/killerbeez/'
APP = 'wmp_windows_x86_64'
COMMAND_LINE = r'wmp debug radamsa -n 2 -sf "seed" -d "{\"timeout\":20}" -i "{\"coverage_modules\":[\"wmp.exe\"],\"timeout\":10000,\"target_path\":\"C:\\Program Files (x86)\\Windows Media Player\\wmplayer.exe\"}"'
SEED = "1234seed"


def submit_batch(app):
    seed_file = submit_api.FILE_DESC()
    seed_file.source = SEED
    seed_file.mode = 'inline'

    cmd_file = submit_api.FILE_DESC()
    cmd_file.source = '%1 {}'.format(COMMAND_LINE)
    cmd_file.mode = 'inline'

    job = submit_api.JOB_DESC()
    job.files = [seed_file, cmd_file]
    job.rsc_fpops_est = 100

    batch = submit_api.BATCH_DESC()
    batch.project = PROJECT
    batch.authenticator = AUTHENTICATOR
    batch.app_name = app
    batch.jobs = [job]

    return_xml = submit_api.submit_batch(batch)
    try:
        return int(return_xml.find('batch_id').text)
    except ValueError, AttributeError:
        ET.dump(return_xml)
        raise


def get_batch_jobs(batch_id):
    QUERY_BATCH = collections.namedtuple(
        'QUERY_BATCH', ['authenticator', 'project', 'batch_id', 'get_cpu_time',
                        'get_job_details'])

    req = QUERY_BATCH(
        authenticator=AUTHENTICATOR,
        project=PROJECT,
        batch_id=batch_id,
        get_cpu_time=False,
        get_job_details=False,
    )
    batch_info = submit_api.query_batch(req)
    job_ids = []
    for job in batch_info.findall('job'):
        try:
            job_ids.append(int(job.find('id').text))
        except ValueError, AttributeError:
            ET.dump(batch_info)
            raise
    return job_ids


def main():
    batch_id = submit_batch(APP)
    job_ids = get_batch_jobs(batch_id)
    print 'Created batch {} with jobs: {}'.format(str(batch_id), ', '.join(str(id) for id in job_ids))


if __name__ == '__main__':
    main()
