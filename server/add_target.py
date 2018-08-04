#!/usr/bin/env python2

import argparse
import fcntl
import os
import os.path
import shutil
import socket
import subprocess
import sys

import boinc_path_config
from Boinc import configxml, projectxml

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('app')
    parser.add_argument('platforms', nargs=argparse.REMAINDER)
    return parser.parse_args()

def add_app(project_file, name, platform):
    app_name = '{}_{}'.format(name, platform)
    for node in project_file.elements:
        if node._name == 'app' and node.name == app_name:
            print('App {} already in project.xml, not adding app'.format(app_name))
            return

    a = project_file.elements.make_node_and_append('app')
    a.name = app_name
    a.user_friendly_name = '{} running on {}'.format(name, platform)

def create_app_dir(name, platform):
    app_name = '{}_{}'.format(name, platform)
    app_dir = os.path.join('apps', app_name)
    if os.path.exists(app_dir):
        print('App directory {} already exists, not adding app versions'.format(app_dir))
        return

    app_version_dir = os.path.join(app_dir, '1', platform)
    os.makedirs(app_version_dir)

    skel_dir = os.path.join('skel', platform)
    for filename in os.listdir(skel_dir):
        if filename != 'version.xml':
            name, dot, ext = filename.rpartition('.')
            new_filename = ''.join((name, '.', app_name, dot, ext))
            shutil.copyfile(os.path.join(skel_dir, filename),
                            os.path.join(app_version_dir, new_filename))
        else:
            with open(os.path.join(skel_dir, filename)) as template:
                version_xml = template.read().format(app=app_name)
            with open(os.path.join(app_version_dir, filename), 'w') as version_file:
                version_file.write(version_xml)

def create_app_templates(name, platform):
    in_template_path = os.path.join('templates', '{}_{}_in'.format(name, platform))
    if os.path.exists(in_template_path):
        print('Input template {} already exists, not adding templates'.format(in_template_path))
        return
    out_template_path = os.path.join('templates', '{}_{}_out'.format(name, platform))
    if os.path.exists(out_template_path):
        print('Output template {} already exists, not adding templates'.format(out_template_path))
        return

    shutil.copyfile(os.path.join('skel', 'templates', '{}_in'.format(platform)), in_template_path)
    shutil.copyfile(os.path.join('skel', 'templates', '{}_out'.format(platform)), out_template_path)


def add_daemons(config_file, name, platform):
    app_name = '{}_{}'.format(name, platform)
    cmd = 'killerbeez_assimilator.py -app {}'.format(app_name)

    for node in config_file.daemons:
        if node.cmd == cmd:
            print('Assimilator daemon for app {} already exists, not adding it'.format(app_name))
            return

    daemon = config_file.daemons.make_node_and_append('daemon')
    daemon.cmd = cmd
    daemon.pid_file = 'killerbeez_assimilator_{}.pid'.format(app_name)
    daemon.lock_file = 'killerbeez_assimilator_{}.lock'.format(app_name)
    daemon.output = 'killerbeez_assimilator_{}.log'.format(app_name)

    daemon = config_file.daemons.make_node_and_append('daemon')
    daemon.cmd = 'sample_trivial_validator --app {}'.format(app_name)
    daemon.pid_file = 'sample_trivial_validator_{}.pid'.format(app_name)
    daemon.lock_file = 'sample_trivial_validator_{}.lock'.format(app_name)
    daemon.output = 'sample_trivial_validator_{}.log'.format(app_name)

def lock_file(filename):
    os.umask(02)
    file = open(filename,'w')
    fcntl.lockf(file.fileno(), fcntl.LOCK_EX|fcntl.LOCK_NB)


def main():
    args = parse_args()
    if not os.path.isfile('project.xml'):
        print('Must be run from the project directory')
        sys.exit(1)

    hostname = socket.gethostname().split('.')[0]
    lockfile_name = os.path.join('pid_{}'.format(hostname), 'add_target.lock')
    try:
        lock_file(lockfile_name)
    except IOError:
        print('Another {} process is running, please try again'.format(sys.argv[0]))

    project_file = projectxml.ProjectFile('project.xml').read()
    config_file = configxml.ConfigFile('config.xml').read()

    name = args.app
    platforms = args.platforms

    for platform in platforms:
        # Add name_platform to apps in project.xml
        add_app(project_file, name, platform)
        # Create app directory with wrapper, version.xml
        create_app_dir(name, platform)
        create_app_templates(name, platform)
        add_daemons(config_file, name, platform)

    project_file.write()
    config_file.write()
    os.unlink(lockfile_name)

    # Update db from project file
    subprocess.check_call(['bin/xadd'])
    # Restart project
    subprocess.check_call(['bin/stop'])
    subprocess.check_call(['bin/start'])

    print('New app versions installed into apps/{}_*. Make any changes you '
          'need, then run bin/update_versions to install them.'.format(name))

if __name__ == '__main__':
    main()
