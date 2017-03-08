# zoneparse.awk
#
# Introduction
# ============
# Parse DNS zone files, as described in:
#  RFC 1035 (basic description)       https://tools.ietf.org/html/rfc1035
#  RFC 2308 ($TTL extension)          https://tools.ietf.org/html/rfc2308
#  RFC 3597 (TYPE#/CLASS# extensions) https://tools.ietf.org/html/rfc3597
#
# The various constants used in DNS are documented by the IANA:
#  https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
#
# Additional extensions:
#  * We support BIND-specific time extensions, like 1D instead of
#    86400 seconds or 5m instead of 300 seconds.
#  * We support BIND 9's KEYDATA type from the "private use" range.
#
# Note that we don't actually do any parsing on the RDATA yet. It is just
# returned in raw format, so applications will have to do their own
# parsing of that as desired.

# Usage
# =====
# To use the parser, include it in the awk invocation line before your
# script, like this:
#
#    awk -f zoneparse.awk -f myscript.awk
#
# That will define the parsing functions so that they can be used.
#
# To parse a file you initialize the parser and then read the RR
# one by one, something like this:
#
#    zonefile_parse_init(parser_state, filename)
#    while (1) {
#        result = zonefile_next_rr(parser_state, rr)
#        if (result != "entry") {
#            break
#        }
#        printf("%s %s %s %s",
#               rr["ownername"], rr["ttl"], rr["class"], rr["rtype"])
#        for (i=1; i<=rr["rdata-part-cnt"]; i++) {
#            printf(" %s", rr["rdata-part," i])
#        }
#        printf("\n")
#    }
#    if (result != "eof") {
#        print result > "/dev/stderr"
#        exit 1
#    }
#
# The zonefile_next_rr() function fills in the array passed with the
# following variables for the next resource record (RR) found:
#
#   * ownername      - the name of the RR
#   * ttl            - the time-to-live (TTL) of the RR (in seconds)
#   * class          - the DNS class of the RR (usually "IN")
#   * class-value    - the numeric value of the class
#   * rtype          - the DNS type of the RR (like "A", "MX", and so on)
#   * rdata-part-cnt - number of parts to the RDATA
#   * rdata-part,#   - each part of the RDATA (# is 1 to rdata-part-cnt)

# TODO: actually process RDATA
# TODO: parse_file_name/$INCLUDE handling
# TODO: @ support in RDATA, and maybe file-name
# TODO: preserve raw version of each entry
# TODO: also return short version of the TTL
# TODO: convert TYPE# and CLASS# to symbolic names if we know them

# BUG: We only support parenthesis or quoted strings in RDATA, but
#      those can appear anywhere.


BEGIN {
    # We initialize a few arrays based on constants assigned by IANA:
    #  https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml

    CLASS["IN"] = 1
    CLASS["CH"] = 3
    CLASS["HS"] = 4

    RRTYPE["A"] = 1
    RRTYPE["NS"] = 2
    RRTYPE["CNAME"] = 5
    RRTYPE["SOA"] = 6
    RRTYPE["PTR"] = 12
    RRTYPE["MX"] = 15
    RRTYPE["TXT"] = 16
    RRTYPE["AAAA"] = 28
    RRTYPE["SRV"] = 33
    RRTYPE["DNAME"] = 39
    RRTYPE["DS"] = 43
    RRTYPE["SSHFP"] = 44
    RRTYPE["RRSIG"] = 46
    RRTYPE["NSEC"] = 47
    RRTYPE["DNSKEY"] = 48
    RRTYPE["DHCID"] = 49
    RRTYPE["NSEC3"] = 50
    RRTYPE["NSEC3PARAM"] = 51
    RRTYPE["SPF"] = 99

    # BIND 9 extension used for RFC5011 trust anchor storage
    RRTYPE["KEYDATA"] = 65533
}

function parse_ttl(str, entry)
{
    if (toupper(str) ~ /^([0-9]+[SMHDW]?)+[ \t]/) {
        ttl = 0
        do {
            if (str ~ /^[0-9]+[wW]/) {
                ttl += (0+str) * (7*24*60*60)
                sub(/^[0-9]+[wW]/, "", str)
            } else if (str ~ /^[0-9]+[dD]/) {
                ttl += (0+str) * (24*60*60)
                sub(/^[0-9]+[dD]/, "", str)
            } else if (str ~ /^[0-9]+[hH]/) {
                ttl += (0+str) * (60*60)
                sub(/^[0-9]+[hH]/, "", str)
            } else if (str ~ /^[0-9]+[mM]/) {
                ttl += (0+str) * 60
                sub(/^[0-9]+[mM]/, "", str)
            } else {
                ttl += (0+str)
                sub(/^[0-9]+[sS]?/, "", str)
            }
        } while (str !~ /^[ \t]/)
        entry["ttl"] = ttl
        if (entry["ttl"] >= 4294967296) {
            printf "TTL %d too big on line %d\n", entry["ttl"],
                   NR > "/dev/stderr"
            exit 1
        }
        sub(/^[ \t]+/, "", str)
    }
    return str
}

function parse_class(str, entry)
{
    if (str ~ /^[A-Za-z0-9-]+[ \t]/) {
        n = match(str, /[ \t]/)
        class = toupper(substr(str, 1, n-1))
        class_value = CLASS[class]
        if (class_value > 0) {
            entry["class"] = class
            entry["class-value"] = class_value
            sub(/^[A-Za-z0-9-]+[ \t]+/, "", str)
        } else if (class ~ /^CLASS[1-9][0-9]+$/) {
            class_value = 0+substr(class, 6)
            if (class_value > 65535) {
                printf "CLASS %d too big on line %d\n", class_value,
                       NR > "/dev/stderr"
                exit 1
            }
            entry["class"] = class
            entry["class-value"] = class_value
            sub(/^[A-Za-z0-9-]+[ \t]+/, "", str)
        }
    }
    return str
}

function parse_rtype(str, entry)
{
    if (str ~ /^[A-Za-z0-9-]+[ \t]/) {
        n = match(str, /[ \t]/)
        rtype = toupper(substr(str, 1, n-1))
        rtype_value = RRTYPE[rtype]
        if (rtype_value > 0) {
            entry["rtype"] = rtype
            entry["rtype-value"] = rtype_value
            sub(/^[A-Za-z0-9-]+[ \t]+/, "", str)
        } else if (rtype ~ /^TYPE[1-9][0-9]+$/) {
            rtype_value = 0+substr(rtype, 6)
            if (rtype > 65535) {
                printf "TYPE %d too big on line %d\n", rtype_value,
                       NR > "/dev/stderr"
                exit 1
            }
            entry["rtype"] = rtype
            entry["rtype-value"] = rtype_value
            sub(/^[A-Za-z0-9-]+[ \t]+/, "", str)
        } else {
            entry["rtype-unknown"] = rtype
        }
    }
    return str
}

# XXX: should handle multi-line
function parse_file_name(str, entry)
{
        str = parse_file_name(str, entry)
}

function add_part(new_part, entry)
{
    if (entry["rdata-part-add"] > entry["rdata-part-cnt"]) {
        entry["rdata-part-cnt"] = entry["rdata-part-add"]
        rdata_part = new_part
    } else {
        rdata_part = entry["rdata-part," entry["rdata-part-cnt"]] new_part
    }
    entry["rdata-part," entry["rdata-part-cnt"]] = rdata_part
}

function parse_rdata(state, str, entry)
{
    while (1) {
        # remove any leading whitespace
        if (str ~ /^[ \t]/) {
            sub(/^[ \t]+/, "", str)
            if (entry["rdata-part-add"] <= entry["rdata-part-cnt"]) {
                entry["rdata-part-add"] += 1
            }
        }

        if (str == "") {
            break
        }

        # quoted string
        if (str ~ /^"([^"]|\\")*"/) {
            match(str, /^"([^"]|\\")*"/)
            add_part(substr(str, 2, RLENGTH-2), entry)
            str = substr(str, RLENGTH+1)

        # quoted string that doesn't end
        } else if (str ~ /^"/) {
            add_part(substr(str, 2), entry)
            state["in-quoted-string"] = "true"
            state["quoted-string-line"] = NR
            str = ""

        # octal-encoded character
        } else if (str ~ /^\\[0-7][0-7][0-7]/) {
            val = (substr(str, 2, 1) * 64) + \
                  (substr(str, 3, 1) * 8) + \
                   substr(str, 4, 1)
            add_part(sprintf("%c", val), entry)
            str = substr(str, 5)

        # some other quoted character
        } else if (str ~ /^\\[^0-9]/) {
            add_part(substr(str, 2, 1), entry)
            str = substr(str, 3)

        # start parentheses
        } else if (str ~ /^\(/) {
            if (state["in-parentheses"] == "true") {
                printf "Nested parentheses not allowed on line %d\n",
                       NR > "/dev/stderr"
                exit 1
            }
            state["in-parentheses"] = "true"
            state["parenthesis-line"] = NR
            str = substr(str, 2)

        # end parentheses
        } else if (str ~ /^\)/) {
            if (state["in-parentheses"] == "false") {
                printf "Close parenthesis without opening parenthesis on line %d\n",
                       NR > "/dev/stderr"
                exit 1
            }
            str = substr(str, 2)
            state["in-parentheses"] = "false"

        # comment ends the line
        } else if (str ~ /^;/) {
            str = ""
            break

        # otherwise consume the characters as the RDATA
        } else {
            match(str, /^[^ \t]+/)
            add_part(substr(str, 1, RLENGTH), entry)
            str = substr(str, RLENGTH+1)

        }

    }

    return str
}

function parse_rr(state, str, entry)
{
    str = parse_ttl(str, entry)
    if (entry["ttl"] == "") {
        str = parse_class(str, entry)
        str = parse_ttl(str, entry)
    } else {
        str = parse_class(str, entry)
    }

    if (entry["ttl"] == "") {
        if (state["ttl"] == "") {
            printf "Missing TTL for RR on line %d\n", NR > "/dev/stderr"
            exit 1
        }
        entry["ttl"] = state["ttl"]
    }
    if (entry["class"] == "") {
        if (state["class"] == "") {
            printf "Missing class for RR on line %d\n", NR > "/dev/stderr"
            exit 1
        }
        entry["class"] = state["class"]
    }

    str = parse_rtype(str, entry)
    if (entry["rtype"] == "") {
        printf "Unknown RTYPE %s on line %d\n",
               entry["rtype-unknown"], NR > "/dev/stderr"
        exit 1
    }

    str = parse_rdata(state, str, entry)

    # save the TTL and CLASS for future entries
    state["ttl"] = entry["ttl"]
    state["class"] = entry["class"]

    return str
}

function parse_domain_name(state, str, entry)
{
    if (str ~ /^(([A-Za-z0-9-]+\.?)+|\.)([ \t]|$)/) {
        n = match(str, /([ \t]|$)/)
        entry["domain-name"] = tolower(substr(str, 1, n-1))
        sub(/^[A-Za-z0-9.-]+[ \t]*/, "", str)
    } else if (str ~ /^@([ \t]|$)/) {
        if (state["origin"] == "") {
            entry["domain-name"] = "."
        } else {
            entry["domain-name"] = state["origin"]
        }
        sub(/^@[ \t]*/, "", str)
    }
    return str
}

function parse_zone_entry(state, str, entry)
{
    # comment lines
    if (str ~ /^[ \t]*(;|$)/) {
        str = ""
        entry["type"] = "empty"

    # if a non-comment line starts with blank space, it is an RR
    } else if (str ~ /^[ \t]/) {
        # remove the blank space that we just found
        sub(/^[ \t]+/, "", str)
        # otherwise we must start with a RR
        if (state["ownername"] == "") {
            printf "No previous RR for entry without domain-name on line %d\n",
                   NR > "/dev/stderr"
            exit 1
        }
        str = parse_rr(state, str, entry)
        entry["ownername"] = state["ownername"]
        entry["type"] = "rr"

    } else if (tolower(str) ~ /^\$origin[ \t]+/) {
        # remove the "$ORIGIN" that we just found
        str = substr(str, length("$ORIGIN")+1)
        sub(/^[ \t]+/, "", str)
        # parse the domain name
        str = parse_domain_name(state, str, entry)
        if (entry["domain-name"] == "") {
            printf "Error parsing domain name for $ORIGIN on line %d\n",
                   NR > "/dev/stderr"
            exit 1
        }
        # set new origin, which may actually be based on prior origin!
        if (entry["domain-name"] ~ /\.$/) {
            if (entry["domain-name"] == ".") {
                state["origin"] = ""
            } else {
                state["origin"] = entry["domain-name"]
            }
        } else {
            state["origin"] = entry["domain-name"] "." state["origin"]
        }
        entry["type"] = "$origin"

    } else if (tolower(str) ~ /^\$include[ \t]+/) {
        # remove the "$INCLUDE" that we just found
        str = substr(str, length("$INCLUDE")+1)
        sub(/^[ \t]+/, "", str)
        # parse the file name
        str = parse_file_name(str, entry)
        if (entry["file-name"] == "") {
            printf "Error parsing file name for $INCLUDE on line %d\n",
                   NR > "/dev/stderr"
            exit 1
        }
        # parse the domain name, if present
        str = parse_domain_name(state, str, entry)
        entry["type"] = "$include"

    } else if (tolower(str) ~ /^\$ttl[ \t]+[0-9]+/) {
        # remove the "$TTL" that we just found
        str = substr(str, length("$TTL")+1)
        # grab the TTL
        state["ttl"] = 0+str
        # remove from the string
        sub(/^[ \t]+[0-9]+/, "", str)
        entry["type"] = "$ttl"

    } else {
        str = parse_domain_name(state, str, entry)
        if (entry["domain-name"] == "") {
            printf "Error parsing domain name for RR on line %d\n",
                   NR > "/dev/stderr"
            exit 1
        }
        # get absolute ownername
        if (entry["domain-name"] ~ /\.$/) {
            entry["ownername"] = entry["domain-name"]
        } else {
            entry["ownername"] = entry["domain-name"] "." state["origin"]
        }
        # save ownername for future uses
        state["ownername"] = entry["ownername"]

        str = parse_rr(state, str, entry)
        entry["type"] = "rr"
    }

    # check for extra stuff at end of line
    sub(/^[ \t]*/, "", str)
    if (str !~ /^[ \t]*(;.*)?$/) {
        printf "Syntax error on line %d, '%s' unexpected\n",
               NR, str > "/dev/stderr"
        exit 1
    }
}

function parse_continued_zone_entry(state, str, entry)
{
    if (state["in-quoted-string"] == "true") {
        n = match(str, /(^"|[^\\]")/)

        # if we don't find a closing quote, add the entire line as a string
        if (n <= 0) {
            add_part(str, entry)
            return
        }

        # otherwise add the line up to the closing quote
        add_part(substr(str, 1, n), entry)

        # remove the string that we go, and end the quoted string
        str = substr(str, n+2)
        state["in-quoted-string"] = "false"
    }

    str = parse_rdata(state, str, entry)

    # check for extra stuff at end of line
    sub(/^[ \t]*/, "", str)
    if (str !~ /^[ \t]*(;.*)?$/) {
        printf "Syntax error on line %d, '%s' unexpected\n",
               NR, str > "/dev/stderr"
        exit 1
    }
}

# Initialize the zone parser.
#
# parameters:
# * state: array initialized with zonefile_parse_init()
# * file: name of the file to process
#
# If the file is "-", then STDIN is used.
#
# Note that no error checking is done. An invalid file will be
# detected when parsing is attempted.
function zonefile_parse_init(state, file)
{
    # clear out any prior state
    for (v in state) {
        delete state[v]
    }

    # initialize the state of our parser
    state["filename"] = file
    state["ownername"] = ""
    state["origin"] = ""
    state["ttl"] = -1
    state["class"] = "IN"
    state["class-value"] = CLASS["IN"]
    state["in-parentheses"] = "false"
    state["parenthesis-line"] = -1
    state["in-quoted-string"] = "false"
    state["quoted-string-line"] = -1
}

function zonefile_parse_is_continuing(state)
{
    if (state["in-parentheses"] == "true") {
        return 1
    }
    if (state["in-quoted-string"] == "true") {
        return 1
    }
    return 0
}

# Return the next entry from a zone file.
#
# Generally the zonefile_next_rr() function is more useful.
#
# parameters:
# * state: array initialized with zonefile_parse_init()
# * entry: array returning details of the next entry found
#
# returns:
# * "entry" if an entry is read
# * "eof" on end-of-file
# * an error string, starting with "Error:", which describes the problem
#
# An entry may be:
# * "empty" for just whitespace
# * "rr" for a resource record (RR)
# * "$ttl" for a $TTL directive
# * "$origin" for an $ORIGIN directive
#
# Note that the entry array is always modified, but should only be
# used if "entry" is returned.
function zonefile_parse_next(state, entry)
{
    # clear anything out of entry
    for (v in entry) {
        delete entry[v]
    }

    # make a new entry
    entry["type"] = ""
    entry["rdata-part-cnt"] = 0
    entry["rdata-part-add"] = 1

    # read another line and start parsing
    filename = state["filename"]
    if (filename == "-") {
        read_result = getline line
    } else {
        read_result = getline line < filename
    }
    if (read_result == 1) {
        # parse the entry
        parse_zone_entry(state, line, entry)

        # if the entry continues, read more lines and keep parsing
        while (zonefile_parse_is_continuing(state)) {

            # read another line
            if (filename == "-") {
                read_result = getline line
            } else {
                read_result = getline line < filename
            }

            # if we are out of input, then we have an error
            if (read_result != 1) {
                if (state["in-parentheses"] == "true") {
                    err = sprintf("Error: missing closing parenthesis for "\
                                  "open parenthesis on line %d\n",
                                  state["parenthesis-line"])
                } else if (state["in-quoted-string"] == "true") {
                    err = sprintf("Error: missing closing quote for string "\
                                  "starting on line %d\n",
                                  state["quoted-string-line"])
                } else {
                    print "Invalid state on EOF" > "/dev/stderr"
                    exit 1
                }
                return err
            }

            # continue to parse the entry with the new line
            parse_continued_zone_entry(state, line, entry)
        }

        return "entry"
    } else {
        return "eof"
    }
}

# Return the next resource record (RR) from a zone file.
#
# parameters:
# * state: array initialized with zonefile_parse_init()
# * entry: array returning details of the next RR found
#
# returns:
# * "entry" if a RR is found
# * "eof" on end-of-file
# * an error string, starting with "Error:", which describes the problem
#
# Note that the entry array is always modified, but should only be
# used if "entry" is returned.
function zonefile_next_rr(state, entry)
{
    # read entries, skipping everything but RR
    while (1) {
        result = zonefile_parse_next(state, entry)
        # if the result is not "entry", it is "eof" or "error"
        if (result != "entry") {
            return result
        }
        # if we got a RR, then we are done
        if (entry["type"] == "rr") {
            return result
        }
    }
}

