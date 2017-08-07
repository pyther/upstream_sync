#!/usr/bin/python -Ott

import sys
from optparse import OptionParser, OptionError
import subprocess
import os
import re
import ConfigParser
import getpass
import OpenSSL
import datetime
import glob
import logging

# Declare variables
mirror_dir = '/mirror/upstream'
confd_dir = '/etc/upstream_sync'

# directory that contains authentication credentials for sles
sles_auth_cred_dir = '/etc/nccs/sles_mirror'

# directory to store generated repo confs
user = getpass.getuser()
tmp_dir = '/var/tmp/upstream_sync-{0}'.format(user)


def make_dir(dir_path, mode=None):
    """ checks if a directory exists and create it if necessary
    :param mode: mode for makedirs
    :param dir_path: dir path for check

    :return: None
    """
    if not os.path.isdir(dir_path):
        # set current umask if not defined as parameter
        try:
            if mode:
                os.makedirs(dir_path, mode)
            else:
                os.makedirs(dir_path)
        except OSError as e:
            print e
            sys.exit(1)


def build_yum_config(name, url, sslcacert, sslcert, sslkey, exclude):
    # Check tmp path exist
    make_dir(tmp_dir)
    repo_conf = os.path.join(tmp_dir, '{0}.repo'.format(name))

    f = open(repo_conf, 'w')
    f.write('[main]\n')
    f.write('reposdir=/dev/null\n')
    f.write('[{0}]\n'.format(name))
    f.write('name = {0}\n'.format(name))
    f.write('baseurl = {0}\n'.format(url))
    f.write('enabled = 1\n')
    f.write('gpgcheck = 0\n')

    if sslcacert and sslcert and sslkey:
        check_sslcert_expiration(sslcert)
        f.write('sslverify = 1\n')
        f.write('sslcacert = {0}\n'.format(sslcacert))
        f.write('sslclientcert = {0}\n'.format(sslcert))
        f.write('sslclientkey = {0}\n'.format(sslkey))

    if exclude:
        f.write('exclude = {0}\n'.format(exclude))

    f.write('metadata_expire = 60\n')

    f.close()

    return repo_conf


def check_sslcert_expiration(sslcert):
    """checks to see if the ssl cert is going to expire soon"""
    try:
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, file(sslcert).read())
        cert_expires = datetime.datetime.strptime(cert.get_notAfter(), "%Y%m%d%H%M%SZ")
    except IOError:
        return

    if datetime.datetime.now() > cert_expires:
        logging.warn('SSL Certificate (%s) expired on %s' % (sslcert, cert_expires))
    elif datetime.datetime.now()+datetime.timedelta(days=14) > cert_expires:
        logging.warn('SSL Certificate (%s) is going to expire on %s' % (sslcert, cert_expires))

    return


def parse_config_auth():
    """ returns dictionary of authentication keys """
    config = ConfigParser.ConfigParser()
    config.read(os.path.join(confd_dir, 'auth.conf'))

    auths = dict()

    for title in config.sections():
        items = dict(config.items(title))
        auths[title] = items

    return auths


def config_repos(rfilter=None):
    """
    parse configuration files and return repos.

    if rfilter is set, only repos that match rfilter will be returned
    """
    defaults = {
        'createrepo': 'False',
        'copylinks': 'False',
        'exclude': '',
    }
    config = ConfigParser.ConfigParser(defaults)
    config.read(glob.glob(os.path.join(confd_dir, '*.repo')))

    auths = parse_config_auth()

    # sort all the repos by alpha order, ConfigParser return sections
    # in the order that they appear in the config file
    repos = []
    for title in config.sections():
        if rfilter and (title not in rfilter):
            continue
        repo = dict(config.items(title))
        repo['name'] = title
        repo['path'] = os.path.join(mirror_dir, repo['path'])  # absolute path of repository
        if repo.has_key('auth'):
            repo['auth'] = auths[repo['auth']]
        repos.append(repo)

    repos = sorted(repos, key=lambda k: k['name'])
    return repos


def list_repos(repos):
    for repo in repos:
        print repo['name']


def sync_cmd_reposync(repo):
    sslcacert = None
    sslcert = None
    sslkey = None
    exclude = None

    reposync_opts = []

    name = repo['name']
    url = repo['url']
    path = repo['path']

    if repo.has_key('auth'):
        auth = repo['auth']
        sslcacert = auth['sslcacert']
        sslcert = auth['sslcert']
        sslkey = auth['sslkey']

    if repo.has_key('exclude'):
        exclude_list = repo['exclude'].split(',')
        # split() will return an empty list element
        if exclude_list:
            exclude = ' '.strip().join(exclude_list)

    yum_conf = build_yum_config(name, url, sslcacert, sslcert, sslkey, exclude)

    reposync_opts.extend(('-c', yum_conf))
    reposync_opts.extend(('-r', name))
    reposync_opts.extend(('-p', path))

    # detect arch
    match_arch = re.match(r'.*(?:/|-)(ppc64|ppc64le|x86_64|i386|i686|armhfp|amd64|x86|aarch64)(?:/|$)', url)
    # detect a mirror of srpms(so .src.rpm files will get mirrored), See --source option to reposync
    match_source = re.match(r'.*(?:/|-)(srpms|SRPMS)(?:/|$)', url)
    if match_arch:
        arch = match_arch.groups()[0]
        if arch in ['i386', 'x86']:
            arch = 'i686'
        elif arch in ['amd64', 'x86_64']:
            arch = 'x86_64'
        reposync_opts.extend(('--arch', arch))

    if match_source:
        reposync_opts.extend(('--source', ))

    if not (match_arch or match_source):
        logging.warn('unable to detect architecture for %s' % name)

    # build options
    if repo.has_key('sync_opts'):
        opt_list = repo['sync_opts'].split()
        for opt in opt_list:
            reposync_opts.append(opt)
    else:
        reposync_opts.append('--tempcache')
        reposync_opts.append('--norepopath')
        reposync_opts.append('--downloadcomps')
        reposync_opts.append('--newest-only')
        reposync_opts.append('--delete')

    # be quiet if verbose is not set
    if not verbose:
        reposync_opts.append('-q')

    sync_cmd = ['reposync'] + reposync_opts
    return sync_cmd


def sync_cmd_rhnget(repo):
    systemid = os.path.join(os.path.split(repo['path'])[0], 'systemid')
    if not os.path.isfile(systemid):
        logging.warn("rhn: can not find systemid (%s)" % systemid)
        return

    sync_cmd = ['rhnget', '-q', '-s', systemid, repo['url'], repo['path']]
    return sync_cmd


def sync_cmd_rsync(repo):
    try:
        username = repo['auth']['user']
    except KeyError:
        url = repo['url']
    else:
        s = repo['url'].split('//', 1)
        s.insert(1, '//{0}@'.format(username))
        url = ''.join(s)

    try:
        password = repo['auth']['password']
    except KeyError:
        password = ''

    logging.debug('set RSYNC_PASSWORD environment variable')
    os.environ["RSYNC_PASSWORD"] = password

    rsync_opts = []
    # build options
    if repo.has_key('sync_opts'):
        opt_list = repo['sync_opts'].split()
        for opt in opt_list:
            rsync_opts.append(opt)
    else:
        rsync_opts.append('--no-motd')
        rsync_opts.append('--recursive')
        rsync_opts.append('--delete')
        rsync_opts.append('--times')
        rsync_opts.append('--contimeout=30')

    if repo['copylinks'].lower() == 'true':
        rsync_opts.append('--copy-links')

    exclude_list = repo['exclude'].split(',')
    for item in exclude_list:
        # split() will return an empty list element
        if item:
            rsync_opts.append('--exclude')
            rsync_opts.append(item)

    if verbose:
        rsync_opts.append('--itemize-changes')

    sync_cmd = ['rsync'] + rsync_opts + [url, repo['path']]
    return sync_cmd


def sync_cmd_you(repo):
    # checking for sles credentials
    deviceid = os.path.join(sles_auth_cred_dir, 'deviceid')
    secret = os.path.join(sles_auth_cred_dir, 'secret')

    if not os.path.isfile(deviceid):
        logging.warn("you: can not find deviceid file (%s)" % deviceid)
        return
    elif not os.path.isfile(secret):
        logging.warn('you: can not find secret file (%s)' % secret)
        return

    url = re.sub('^you://', 'https://', repo['url'])
    sync_cmd = ['/opt/bin/youget', '-q', '--source', '-d', sles_auth_cred_dir, '--delete', url, repo['path']]

    return sync_cmd


def main():
    """main subroutine"""

    parser = OptionParser()
    parser.add_option("-v", "--verbose", help="Be verbose", action="count")
    parser.add_option("-l", "--list", help="list repos", action="store_true")
    parser.add_option("-c", "--command", help="print the sync command", action="store_true")
    parser.add_option("-r", "--repos", help="syncs specific repo(s) (comma seperated list)", dest="rfilter")
    parser.add_option("--root", help="run script as root", action="store_true")
    try:
        (options, args) = parser.parse_args()
    except OptionError:
        parser.print_help()
        return 1

    global verbose
    if options.verbose:
        logging.basicConfig(level=logging.DEBUG)
        verbose = True
    else:
        logging.basicConfig(level=logging.WARNING)
        verbose = False

    show_command = options.command
    run_as_root = options.root

    # get repos from config
    if options.rfilter:
        repos = config_repos(rfilter=options.rfilter.split(','))
    else:
        repos = config_repos()

    # list repos
    if options.list:
        list_repos(repos)
        sys.exit(0)

    if not run_as_root:
        if os.geteuid() == 0:
            print("It is strongly advised not to run this script as root!")
            print("Running as root will most likely mess up filesystem permissions.")
            print("If you are sure you want to run as root, pass --root")
            sys.exit(2)

    if not show_command:
        make_dir(confd_dir)

    for repo in repos:
        # set variables based on values in config
        url = repo['url']
        name = repo['name']
        path = os.path.join(mirror_dir, repo['path'])  # absolute path of repository

        # create repo directory
        if not show_command:
            make_dir(path, 0775)

        createrepo = False
        if repo['createrepo'].lower() == "true":
            createrepo = True

        # Generate the sync and createrepo commands to be used based on repository type
        createrepo_exec = ['createrepo']
        createrepo_opts = ['--pretty', '--database', '--update', '--cachedir', os.path.join(path, '.cache'), path]
        if not options.verbose:
            createrepo_opts.append('-q')

        if re.match('^(http|https|ftp)://', url):
            sync_cmd = sync_cmd_reposync(repo)
        elif re.match('^rhns:///', url):
            sync_cmd = sync_cmd_rhnget(repo)
        elif re.match('^you://', url):
            sync_cmd = sync_cmd_you(repo)
        elif re.match('^rsync://', url):
            sync_cmd = sync_cmd_rsync(repo)
        else:
            logging.warn('url type unknown - %s' % url)
            continue

        if not sync_cmd:
            continue

        # if option -c is passed print commands and continue to loop item
        if show_command:
            print('%s:' % name)
            print('  '+' '.join(sync_cmd))
            if createrepo:
                print('  '+' '.join(createrepo_exec + createrepo_opts))
            continue

        # preform sync - rhnget/rsync
        logging.info('syncing %s' % name)
        if options.verbose:
            stdout_pipe = sys.stdout
            stderr_pipe = sys.stderr
        else:
            stdout_pipe = subprocess.PIPE
            stderr_pipe = subprocess.STDOUT

        p1 = subprocess.Popen(sync_cmd, stdout=stdout_pipe, stderr=stderr_pipe, stdin=subprocess.PIPE)
        p1_rc = p1.wait()
        stdout, _ = p1.communicate()

        # display output if the sync fails
        if p1_rc > 0:
            if not options.verbose:
                logging.warn(stdout)
            logging.warn('sync failed: %s' % name)
            continue  # no need to run createrepo if sync failed

        # run createrepo to generate package metadata
        if createrepo:
            logging.info('generating package metadata: {0}'.format(name))

            # if comps.xml exists, use it to generate group data
            comps_file = os.path.join(path, 'comps.xml')
            if os.path.isfile(comps_file):
                createrepo_opts = ['-g', comps_file] + createrepo_opts

            createrepo_cmd = createrepo_exec + createrepo_opts

            p2 = subprocess.Popen(createrepo_cmd, stdout=stdout_pipe, stderr=stderr_pipe, stdin=subprocess.PIPE)
            p2_rc = p2.wait()
            stdout, _ = p2.communicate()

            if p2_rc > 0:
                if not options.verbose:
                    logging.warn(stdout)
                logging.warn('createrepo failed: %s' % name)


if __name__ == "__main__":
    sys.exit(main())

