# rr2keytag.awk
#
# Introduction
# ============
# Build a key tag from the trusted key in the parsed file.
# 
# The key tag format is documented in:
#   https://tools.ietf.org/html/draft-ietf-dnsop-edns-key-tag-05
#
#
# Invocation
# ==========
# Run the script like this:
#
#     $ awk -f zoneparse.awk -f rr2keytag.awk trusted-key.key
#     dig -t null -c in _ta-4a5c.


# This is a direct translation from the C reference implementation.
# Since awk doesn't have bitwise operations, we do the same thing
# with multiplication, division, and modulo operations. This is of
# course very slow. It can surely be made much faster with
# re-factoring, but since we only invoke this for trust anchors,
# which are normally only have a few configured per resolver, speed
# does not matter.
# 
# https://tools.ietf.org/html/rfc4034#appendix-B
function keytag(key) {
    ac = 0
    for (i=0; i in key; i++) {
        c = key[i]
        ac += (i % 2) ? c : (c * 256)
    }
    ac += int(ac / 65536)
    return ac % 65536
}

# Here we implement Base64 decoding.
#
# https://tools.ietf.org/html/rfc3548
#
# We exit on error. For a general function this should be changed to
# returning an error code somehow.

# create our lookup table
BEGIN {
    # load symbols based on the alphabet
    for (i=0; i<26; i++) {
        BASE64[sprintf("%c", i+65)] = i
        BASE64[sprintf("%c", i+97)] = i+26
    }
    # load our numbers
    for (i=0; i<10; i++) {
        BASE64[sprintf("%c", i+48)] = i+52
    }
    # and finally our two additional characters
    BASE64["+"] = 62
    BASE64["/"] = 63
    # also add in our padding character
    BASE64["="] = -1
}

function base64decode_into(encoded, result, n) {
    while (length(encoded) >= 4) {
        g0 = BASE64[substr(encoded, 1, 1)]
        g1 = BASE64[substr(encoded, 2, 1)]
        g2 = BASE64[substr(encoded, 3, 1)]
        g3 = BASE64[substr(encoded, 4, 1)]
        if (g0 == "") {
            printf("Unrecognized character %c in Base 64 encoded string\n",
                   g0) >> "/dev/stderr"
            exit 1
        }
        if (g1 == "") {
            printf("Unrecognized character %c in Base 64 encoded string\n",
                   g1) >> "/dev/stderr"
            exit 1
        }
        if (g2 == "") {
            printf("Unrecognized character %c in Base 64 encoded string\n",
                   g2) >> "/dev/stderr"
            exit 1
        }
        if (g3 == "") {
            printf("Unrecognized character %c in Base 64 encoded string\n",
                   g3) >> "/dev/stderr"
            exit 1
        }

        # we don't have bit shifting in AWK, but we can achieve the same
        # results with multiplication, division, and modulo arithmetic
        result[n++] = (g0 * 4) + int(g1 / 16)
        if (g2 != -1) {
            result[n++] = ((g1 * 16) % 256) + int(g2 / 4)
            if (g3 != -1) {
                result[n++] = ((g2 * 64) % 256) + g3
            }
        }

        encoded = substr(encoded, 5)
    }
    if (length(encoded) != 0) {
        printf("Extra characters at end of Base 64 encoded string: \"%s\"\n",
               encoded) >> "/dev/stderr"
        exit 1
    }
}

function zone2keytag(file, keytags)
{
    zonefile_parse_init(parser_state, file)
    while (1) {
        result = zonefile_next_rr(parser_state, rr)
        if (result != "entry") {
            break
        }
        if (rr["class"] != "IN") {
            continue
        }

        if (rr["rtype"] == "DNSKEY") {
            # We need to convert from the presentation to the wire format
            # https://tools.ietf.org/html/rfc4034#section-2.2

            # flags is a 2-byte field
            rdata[0] = int(rr["rdata-part,1"] / 256)
            rdata[1] = rr["rdata-part,1"] % 256

            # protocol is 1-byte
            rdata[2] = 0+rr["rdata-part,2"]

            # algorithm is 1-byte
            # TODO: support mnemonics
            #       https://tools.ietf.org/html/rfc4034#appendix-A.1
            rdata[3] = 0+rr["rdata-part,3"]

            # finally we collect the Base64 encoded public key
            base64 = ""
            for (i=4; i<=rr["rdata-part-cnt"]; i++) {
                s = rr["rdata-part," i]
                gsub(/[ \t]+/, "", s)
                base64 = base64 s
            }
            base64decode_into(base64, rdata, 4)
            kt_field = keytag(rdata)
            kt_zone = rr["ownername"]

        } else if (rr["rtype"] == "DS") {
            # DS records include the key tag directly
            kt_field = 0+rr["rdata-part,1"]
            kt_zone = rr["ownername"]

        } else {
            continue

        }

        if (kt_zone in keytags) {
            keytags[kt_zone] = keytags[kt_zone] ":" kt_field
        } else {
            keytags[kt_zone] = kt_field
        }
    }
}

# Since AWK doesn't have any built-in sort, we implement our own by
# creating a function that removes the smallest element from an array.
# By calling this repeatedly you will get a sorted result. This yields
# an O(n^2) implementation, and should only be used for very small
# arrays.
function remove_min(arr) {
    # move the smallest to the end of the array
    for (i=2; i in arr; i++) {
        if (arr[i] > arr[i-1]) {
            tmp = arr[i]
            arr[i] = arr[i-1]
            arr[i-1] = tmp
        }
    }
    # save the smallest
    min = arr[i-1]
    # remove it from the arr
    delete arr[i-1]
    # return the smallest
    return min
}

function make_keytag(field, zone) {
    s = "_ta"
    # split the field up into tags based on the colon separator
    split(field, tags, ":")
    # track the previous tag added, so that we remove duplicates
    prev_min = -1
    while (1 in tags) {
        # get the smallest tag, and if we have not seen it add it
        min = remove_min(tags)
        if (min != prev_min) {
            s = s sprintf("-%04x", min)
        }
        prev_min = min
    }
    # quick hack to fix-up the root zone name
    if (zone == ".") {
        zone = ""
    }
    # return our result
    return s "." zone
}

BEGIN {
    if (ARGC == 1) {
        zone2keytag("-", keytags)
    } else {
        for (i=1; i<ARGC; i++) {
            zone2keytag(ARGV[i], keytags)
        }
    }
    for (zone in keytags) {
        printf("dig -t null -c in %s\n", make_keytag(keytags[zone], zone))
    }
}
