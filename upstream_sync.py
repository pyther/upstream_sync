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

## Declare variables
mirror_dir = '/data/mirror/upstream'
repo_conf = '/data/mirror/upstream/repos.conf'

# directory that contains authentication credentials for sles
sles_auth_cred_dir = '/etc/passwords/sles_mirror'

## directory to store generated repo confs
user=getpass.getuser()
tmp_dir = '/var/tmp/upstream_sync-{0}'.format(user)

def debug(msg):
    if verbose:
        print(msg)
    return

def build_yum_config(name,url,sslcacert,sslcert,sslkey):
    # Check tmp path exist
    if not os.path.isdir(tmp_dir):
        os.mkdir(tmp_dir)
    repo_conf = os.path.join(tmp_dir,'{0}.repo'.format(name))

    f = open(repo_conf,'w')
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

    f.write('metadata_expire = 60\n')

    f.close()

    return repo_conf

def check_sslcert_expiration(sslcert):
    "checks to see if the ssl cert is going to expire soon"
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, file(sslcert).read())
    cert_expires = datetime.datetime.strptime(cert.get_notAfter(),"%Y%m%d%H%M%SZ")

    if datetime.datetime.now() > cert_expires:
        print('NOTICE: SSL Certificate ({0}) expired on {1}'.format(sslcert,cert_expires))
    elif datetime.datetime.now()+datetime.timedelta(days=30) > cert_expires:
        print('NOTICE: SSL Certificate ({0}) is going to expire on {1}'.format(sslcert,cert_expires))

    return

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
    verbose = options.verbose
    show_command = options.command
    run_as_root = options.root

    if not run_as_root:
        if os.geteuid() == 0:
            print("It is strongly advised not to run this script as root!")
            print("Running as root will most likely mess up filesystem permissions.")
            print("If you are sure you want to run as root, pass --root")
            sys.exit(2)

    defaults = {'createrepo':'False','copylinks':'False','exclude':'','sslcacert':'','sslcert':'','sslkey':''}
    config = ConfigParser.ConfigParser(defaults)
    config.read(repo_conf)

    # list of repos that user wants to sync
    rfilter=None
    if options.rfilter:
        rfilter = options.rfilter.split(',')

    # sort all the repos by alpha order, ConfigParser return sections
    # in the order that they appear in the config file
    repos = []
    for repo in config.sections():
        if rfilter:
            if repo in rfilter:
                repos.append(repo)
        else:
            repos.append(repo)

    repos = sorted(repos)

    # list repos
    if options.list:
        for repo in repos:
            print(repo)
        sys.exit(0)

    for repo in repos:
        # set variables based on values in config
        url = config.get(repo,'url')
        name = repo
        path = os.path.join(mirror_dir,config.get(repo,'path')) # absolute path of repository

        # create repo directory
        if not show_command:
            if not os.path.isdir(path):
                os.makedirs(path,0775)

        if config.get(repo,'createrepo').lower() == "true":
            createrepo = True
        else:
            createrepo = False

        if config.get(repo,'copylinks').lower() == "true":
            copylinks = True
        else:
            copylinks = False

        exclude_list = config.get(repo,'exclude').split(',')

        # Generate the sync and createrepo commands to be used based on repository type
        createrepo_exec = ['createrepo']
        createrepo_opts = ['-q','--pretty','--database','--update','--cachedir',os.path.join(path,'.cache'),path]
        if re.match('^(http|https)://', url):
            sslcacert = config.get(repo,'sslcacert')
            sslcert = config.get(repo,'sslcert')
            sslkey = config.get(repo,'sslkey')

            yum_conf=build_yum_config(name,url,sslcacert,sslcert,sslkey)

            sync_cmd = ['reposync','-c',yum_conf,'-r',name,'-p',path,'--tempcache','--norepopath','--downloadcomps','--newest-only','--delete','-q']
        elif re.match('^rhns:///', url):
            systemid = os.path.join(os.path.split(path)[0],'systemid')
            if not os.path.isfile(systemid):
                print("rhn: can not find systemid (%s)" % (systemid))
                continue
            sync_cmd = ['rhnget','-q','-s',systemid,url,path]
        elif re.match('^you://',url):
            # checking for sles credentials
            deviceid = os.path.join(sles_auth_cred_dir,'deviceid')
            secret = os.path.join(sles_auth_cred_dir,'secret')

            if not os.path.isfile(deviceid):
                print("you: can not find deviceid file (%s)" % deviceid)
                continue
            elif not os.path.isfile(secret):
                print('you: can not find secret file (%s)' % secret)
                continue

            url = re.sub('^you://','https://',url)
            sync_cmd = ['/opt/bin/youget','-q','--source','-d',sles_auth_cred_dir,'--delete',url,path]
        elif re.match('^rsync://', url):
            rsync_opts = []
            rsync_opts.append('--no-motd')
            rsync_opts.append('--recursive')
            rsync_opts.append('--delete')
            if copylinks:
                rsync_opts.append('--copy-links')
            for item in exclude_list:
                #split() will return an empty list element
                if item:
                    rsync_opts.append('--exclude')
                    rsync_opts.append(item)
            sync_cmd = ['rsync']+rsync_opts+[url,path]
        else:
            print('url type unknown - %s' % (url))
            continue

        # if option -c is passed print commands and continue to loop item
        if show_command:
            print('%s:' % name)
            print('  '+' '.join(sync_cmd))
            if createrepo:
                print('  '+' '.join(createrepo_exec + createrepo_opts))
            continue

        # preform sync - rhnget/rsync
        debug('syncing %s' % (name))
        p1 = subprocess.Popen(sync_cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE)
        p1_output=p1.communicate('\n')
        p1_rc = p1.wait()

        # display output if the sync fails
        if p1_rc > 0:
            print('sync failed: {0}'.format(name))
            print_output(p1_output)
            continue # no need to run createrepo if sync failed
        else:
            print_output(p1_output,d=True) # call debug instead of print (d=True)

        # run createrepo to generate package metadata
        if createrepo:
            debug('generating package metadata: {0}'.format(name))

            # if comps.xml exists, use it to generate group data
            comps_file=os.path.join(path,'comps.xml')
            if os.path.isfile(comps_file):
                createrepo_opts = ['-g', comps_file] + createrepo_opts

            createrepo_cmd = createrepo_exec + createrepo_opts

            p2 = subprocess.Popen(createrepo_cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE)
            p2_output=p2.communicate()
            p2_rc = p2.wait()

            if p2_rc > 0:
                print('createrepo failed: {0}'.format(name))
                print_output(p2_output)
            else:
                print_output(p2_output,d=True) # call debug instead of print (d=True)


def print_output(output,d=False):
    stderr,stdout = output

    # Strip out extra lines / spaces
    stderr = stderr.strip()
    stdout = stdout.strip()

    if stdout:
        if d:
            debug(stdout)
        else:
            print(stdout)
    if stderr:
        if d:
            debug('stderr:')
            debug(stderr)
        else:
            print('stderr:')
            print(stderr)
    return

if __name__ == "__main__":
    sys.exit(main())

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
