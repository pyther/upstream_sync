# upstream_sync
Sync http and https repositories using reposync, rsync repos, and sles using youget.

## Disclaimer
I've had many folks request that I share this script. To comply I am posting as
is. It's certainly not perfect and there is a lot of room for improvement.


## Configuration
  - in `upstream_sync.py` set
    - `mirror_dir` path mirrored content should be stored in
    - `confd_dir`: path to configuration directory (see example)

### Examples
/etc/upstream_sync/auth.conf
```
[rhel-server]
sslcacert = /mirror/certs/redhat-uep.pem
sslcert = /mirror/certs/rhel-server.pem
sslkey = /mirror/certs/rhel-server.pem
```

/etc/upstream_sync/redhat.repo
```
[rhel-7-x86_64-os]
auth = rhel-server
url = https://cdn.redhat.com/content/dist/rhel/server/7/7Server/x86_64/os
path = rhel/7/x86_64/os
createrepo = true

[rhel-6-x86_64-os]
auth = rhel-server
url = https://cdn.redhat.com/content/dist/rhel/server/6/6Server/x86_64/os
path = rhel/6/x86_64/os
createrepo = true
```

/etc/upstream_sync/epel.repo
```
## epel
[epel-5-x86_64]
url = rsync://rsync.gtlib.gatech.edu/fedora-epel/5/x86_64/
path = el/5/x86_64/epel
exclude = /debug/

[epel-6-x86_64]
url = rsync://rsync.gtlib.gatech.edu/fedora-epel/6/x86_64/
path = el/6/x86_64/epel
exclude = /debug/

[epel-7-x86_64]
url = rsync://rsync.gtlib.gatech.edu/fedora-epel/7/x86_64/
path = el/7/x86_64/epel
exclude = /debug/
```

/etc/upstream_sync/centos.repo
```
## centos x86_64
[centos-6.6-x86_64-updates]
url = rsync://rsync.gtlib.gatech.edu/centos/6.6/updates/x86_64/Packages/
path = centos/6.6/x86_64/updates
createrepo = true

[centos-5.11-x86_64-updates]
url = rsync://rsync.gtlib.gatech.edu/centos/5.11/updates/x86_64/RPMS/
path = centos/5.11/x86_64/updates
createrepo = true
```

Override the default reposync options with sync_opts

/etc/upstream_sync/mariadb.repo
```
## mariadb 10.1.12 rhel7
[mariadb-10.1.12-rhel7]
url = http://yum.mariadb.org/10.1.12/rhel7-amd64/
path = mariadb/rhel7/x86_64
sync_opts = --norepopath --tempcache
createrepo = true

[mariadb-10.1.11-rhel7]
url = http://yum.mariadb.org/10.1.11/rhel7-amd64/
path = mariadb/rhel7/x86_64
sync_opts = --norepopath --tempcache
createrepo = true
```

## Usage

List all Repos that are configured
  `./upstream_sync.py -l`

Sync specific repo
  `./upstream_sync.py -r rhel-6-x86_64-updates`

Sync all repos
  `./upsream_sync.py`

Be verbose while syncing
  `./upstream_sync.py -v`

Show sync and createrepo commands
  `./upstream_sync.py -c`

## Mirroring RedHat Repos

RedHat repos use HTTPS with client certificates for authentication. There is no special magic.

Remember, you still must comply with RedHat Licensing!

### Getting the Certificates
The CA can be found on any RHEL system: /etc/rhsm/ca/redhat-uep.pem

To obtain the client certificate and key, you need manually register your
system through the customer portal. You will then assign an entitlement to the
machine. At this point, you can download the entitlement cert/key. This is the
ssl certificate/key that you want to use with this script.

You can test the ssl certificate with this curl command
```$ curl --cacert /etc/rhsm/ca/redhat-uep.pem -E ./rhel.pem --key ./rhel.pem https://cdn.redhat.com/content/dist/rhel/server/7/7Server/x86_64/os```

Of course, adjust the URL as necessary.
