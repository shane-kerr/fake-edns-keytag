# Build a key tag query based on the Unbound configuration.
#
# To run:
#
#    $ awk -f mkdtemp -f unboundtag.awk [config [...]]
#
# This is not actually completely correct, because if a single
# zone has trust anchors defined in multiple files then it will
# produce multiple dig statements. So don't do that!


# If Unbound is configured with a resource record, then we throw it
# into a temporary file and use our normal zone parsing to extract
# out the trust anchor. Possibly this is backwards; having the zone
# parsing call a resource record parser makes more sense, but since
# the code is already written, we do it this way.
function temporary_anchor_file(rr) {
    tmpdir = mkdtemp("/tmp/anchortmp-XXXXXX")
    if (tmpdir == "") {
        print "Unable to make temporary directory" > "/dev/stderr"
        exit 1
    }
    anchor_file = tmpdir "/anchor"
    print "; Temporary zone file for trust anchor" > anchor_file
    print rr >> anchor_file
    close(anchor_file)
    system("awk -f zoneparse.awk -f rr2keytag.awk " anchor_file)
    system("rm -r " tmpdir)
}

function parse_trusted_keys_clause(keyfile) {
    parse_rr = ""
    while ((getline line < keyfile) == 1) {
        if (line ~ /^[ \t]*}[ \t]*;[ \t]*$/) {
            break
        } 
        if (line ~ /^[ \t]*[A-Za-z0-9-]*
            
        }
    }
    return parse_rr
}

function parse_trusted_keys_file(keyfile, keys) {
    keys_rr = ""
    while ((getline line < keyfile) == 1) {
        if (line ~ /^[ \t]*trusted-keys[ \t]*{[ \t]*$/) {
            keys_rr = keys_rr "\n" parse_trusted_keys_clause(keyfile)
        }
    }
    return keys_rr
}

function unbound_make_keytag(cfgfile) {
    trust_anchors = ""
    while ((getline line < cfgfile) == 1) {
        if (line ~ /^[ \t]*include:[ \t]*".*"[ \t]*$/) {
            include_file = line
            sub(/^[ \t]*include:[ \t]*"/, "", include_file)
            sub(/"[ \t]*$/, "", include_file)
            cmd = "find " include_file " -maxdepth 0"
            while ((cmd | getline fname) == 1) {
                unbound_make_keytag(fname)
            }
        } else if (line ~ /^[ \t]*(auto-)?trust-anchor-file:[ \t]*".*"[ \t]*$/) {
            anchor_file = line
            sub(/^[ \t]*(auto-)?trust-anchor-file:[ \t]*"/, "", anchor_file)
            sub(/"[ \t]*$/, "", anchor_file)
            system("awk -f zoneparse.awk -f rr2keytag.awk " anchor_file)
        } else if (line ~ /^[ \t]*trust-anchor:[ \t]*".*"[ \t]*$/) {
            anchor_rr = line
            sub(/^[ \t]*trust-anchor:[ \t]*"/, "", anchor_rr)
            sub(/"[ \t]*$/, "", anchor_rr)
            trust_anchors = trust_anchors "\n" anchor_rr
        } else if (line ~ /^[ \t]*trusted-keys-file:[ \t]*".*"[ \t]*$/) {
            keys_file = line
            sub(/^[ \t]*trusted-keys-file:[ \t]*"/, "", keys_file)
            sub(/"[ \t]*$/, "", keys_file)
#            system("awk -f zoneparse.awk -f rr2keytag.awk " anchor_file)
        }
    }
    temporary_anchor_file(trust_anchors)
}

BEGIN {
    if (ARGC <= 1) {
        # make keytags based on well-known Unbound locations
        unbound_make_keytag("/etc/unbound/unbound.conf")
        unbound_make_keytag("/etc/unbound.conf")
        unbound_make_keytag("/usr/local/etc/unbound/unbound.conf")
        unbound_make_keytag("/usr/local/etc/unbound.conf")
    } else {
        # make keytags for the arguments passed
        for (i=1; i<ARGC; i++) {
            unbound_make_keytag(ARGV[i])
        }
    }
}

