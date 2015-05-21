# upstream_sync
A little script to help mirror upstream repositories.

The script support http:// and https:// repositories using reposync and
rsync:// repostories using rsync. It also supports rhn:// and sles repos,
however don't use those.

## Disclaimer
I've had many folks request that I share this script. To comply I am posting as
is. It's certainly not perfect and there is a lot of room for improvement.


## Configuration
  - in `upstream_sync.py` set
    - `mirror_dir` path mirrored content should be stored in
    - `repo_conf`: path to the upstream.repo configuration file (see example)

## Usage

List all Repos that are configured
  `./upstream_sync.py -l`

Sync specific repo
  `./upstream_sync.py -r rhel-6-x86_64-updates`

Sync all repos
  `./upsream_sync.py`

Be verbose while syncing
  `./upstream_sync.py -v`

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
