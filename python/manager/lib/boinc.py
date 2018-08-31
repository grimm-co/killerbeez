import hashlib
import os.path
import re
import subprocess
import xml.etree.ElementTree as ET

from app import app
from lib import errors

def clean_download_path(path):
    """Turns an absolute path in the BOINC download dir into a relative path.

    This allows paths to be used as URL components, and doesn't expose
    unnecessary server configuration data.
    """
    _, _, relpath = path.rpartition('/download/')
    return relpath


def dir_hier_path(filename):
    """Convert a filename to an absolute path in the BOINC download tree.

    In the download tree, files are stored in a subdirectory based on the hash
    of the filename. This function calls out to BOINC to find the correct path
    for a given filename.
    """
    abspath = subprocess.check_output(
        ['bin/dir_hier_path', filename], cwd=app.config['BOINC_PROJECT_DIR'])
    return abspath.strip().decode('utf8')


def filename_to_download_path(filename):
    """Convert a filename to a path relative to the download directory.

    Given a filename, returns a path that can be appended to the URL of the
    download directory to download that file.
    """
    abspath = dir_hier_path(filename)
    return clean_download_path(abspath)


def stage_file(prefix, contents):
    filename = _filename_for_contents(prefix, contents)
    abspath = dir_hier_path(filename)
    if os.path.exists(abspath):
        with open(abspath, 'rb') as existing:
            if existing.read() != contents:
                raise errors.InternalError(
                    'Attempted to stage {} with differing contents'.format(filename))
    else:
        with open(abspath, 'wb') as new_file:
            new_file.write(contents)
    return abspath

def get_filename(prefix, hash):
    return dir_hier_path('{}_{}'.format(prefix, hash))

def _filename_for_contents(prefix, contents):
    file_hash = hashlib.md5(contents).hexdigest()
    return '{}_{}'.format(prefix, file_hash)


def submit_job(appname, cmdline, seed_file=None, seed_contents=None):
    if seed_file and seed_contents:
        raise errors.InternalError(
            'Only one of seed_file and seed_contents can be specified')

    if seed_contents:
        seed_file = stage_file('input', seed_contents)
    elif not seed_file:
        raise errors.InternalError('No seed specified')

    # TODO: should the cmdline files have guaranteed unique filenames?
    cmd_contents = '%1 {}'.format(cmdline).encode('utf8')
    cmd_file = os.path.basename(stage_file('cmdline', cmd_contents))

    create_work_args = ['bin/create_work', '--appname', appname, '--verbose',
                        seed_file, cmd_file]
    try:
        result = subprocess.check_output(
            create_work_args, cwd=app.config['BOINC_PROJECT_DIR'],
            stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        raise errors.BoincError('create_work returned error: {}'.format(e.output))

    for line in result.splitlines():
        match = re.match(rb'created workunit; .*, ID ([0-9]+)', line)
        if match:
            return int(match.group(1))

    raise errors.BoincError('Could not find ID in create_work output: {}'.format(result))
