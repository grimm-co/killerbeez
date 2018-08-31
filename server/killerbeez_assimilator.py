#!/usr/bin/env python

import logging
import os.path
import re
import shutil
import subprocess
import tempfile
import zipfile

import requests

import assimilator
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

API_SERVER = 'http://localhost:5000/api'


def clean_download_path(path):
    """Turns an absolute path in the BOINC download dir into a relative path.

    This allows paths to be used as URL components, and doesn't expose
    unnecessary server configuration data.
    """
    _, _, relpath = path.rpartition('/download/')
    return relpath


def filename_to_download_path(path):
    abspath = subprocess.check_output(
        ['bin/dir_hier_path', path], cwd='..').strip()
    return clean_download_path(abspath)


def dirname_to_result_type(dirname):
    result_types = {'crashes': 'crash', 'hangs': 'hang', 'new_paths': 'new_path'}
    return result_types[dirname]


class KillerbeezAssimilator(assimilator.Assimilator):
    def __init__(self):
        assimilator.Assimilator.__init__(self)

    def _stage_file(self, filename):
        logger.debug('Staging %s', filename)
        process = subprocess.Popen(
            ['bin/stage_file', '--verbose', filename],
            cwd='..', stdout=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode:
            self.logError('Error staging file: {} | {}\n'.format(stdout, stderr))
            return None

        # Try to parse stdout to find out where the file was staged to
        new_path = None
        for line in stdout.splitlines():
            if line.startswith(b'staging '):
                _, _, path = line.partition(b' to ')
                new_path = path.decode('utf8')
            elif b'already exists as' in line:
                _, _, path = line.partition(b' as ')
                new_path = path.decode('utf8')

        return clean_download_path(new_path)

    def _record_job(self, wu):
        job_id = wu.id
        # ET doesn't like multiple root elements, so we need to wrap the whole
        # document in one element
        xml_doc = ET.fromstring('<xml_doc>{}</xml_doc>'.format(wu.xml_doc))
        file_name_element = xml_doc.find("workunit/file_ref[open_name='seed']/file_name")
        if file_name_element is None:
            return # TODO: error handling
        seed_file = filename_to_download_path(file_name_element.text)
        requests.put('{}/job/{}'.format(API_SERVER, job_id),
                    json={'seed_file': seed_file, 'status': 'completed'})

    def _record_result(self, file_path, result_type, job_id):
        # TODO: use client helper module, maybe
        requests.post('{}/boinc_job/{}/results'.format(API_SERVER, job_id),
                    json={'repro_file': file_path, 'result_type': result_type})

    def _process_zipfile(self, job_id, output_file):
        tempdir = tempfile.mkdtemp()
        try:
            with zipfile.ZipFile(output_file, 'r') as results_file:
                for result_name in results_file.namelist():
                    match = re.match(r'killerbeez_result_([a-z]+)_([A-Za-z0-9]+)', result_name)
                    if not match:
                        continue
                    result_type = match.group(1)
                    md5 = match.group(2)

                    filename = os.path.join(tempdir, 'input_{}'.format(md5.lower()))
                    with open(filename, 'wb') as dest, results_file.open(result_name) as src:
                        dest.write(src.read())

                    staged_path = self._stage_file(filename)
                    self._record_result(staged_path, dirname_to_result_type(result_type), job_id)
        finally:
            shutil.rmtree(tempdir)

    def assimilate_handler(self, wu, results, canonical_result):
        """
        This method is called for each workunit (wu) that needs to be
        processed. A canonical result is not guarenteed and several error
        conditions may be present on the wu. Call report_errors(wu) when
        overriding this method.
        
        Note that the -noinsert flag (self.noinsert) must be accounted for when
        overriding this method.
        """
        if self.report_errors(wu) or canonical_result is None:
            return

        # TODO: handle error status, maybe
        self._record_job(wu)
        zipfile_name = self.get_file_path(canonical_result)
        self._process_zipfile(wu.id, zipfile_name)


if __name__ == '__main__':
    asm = KillerbeezAssimilator()
    asm.run()
