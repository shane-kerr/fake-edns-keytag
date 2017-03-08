# mkdtemp.awk
#
# Introduction
# ============
# Defines a function for creating a temporary directory.
#
# This is modeled after the POSIX mkdtemp() system call, defined by
# the Open Group:
#
# http://pubs.opengroup.org/onlinepubs/9699919799/functions/mkdtemp.html
#
# Note that we implement mkdtemp() rather than mkstemp() because we
# have no equivalent of the "O_CREAT | O_EXCL" flags in AWK to prevent
# us from overwriting or appending to existing files. We might be able
# to rely on the shell "noclobber" setting, but mkdtemp() seemed
# better.
#
# Usage
# =====
# To use the function, include it in the AWK invocation line before
# your script, like this:
#
#     awk -f mkdtemp.awk -f myscript.awk
#
# Using it is straightforward:
#
#     tempdir = mkdtemp("/tmp/fooXXXXXX")
#     if (tempdir == "") {
#         print "Unable to create temporary directory" > "/dev/stderr"
#         exit 1
#     }
#     file = tempdir "/file.dat"
#     print "some data" > file
#      ...
#     system("rm -r " tempdir)

BEGIN {
    # mkdtemp() replaces trailing XXXXXX with characters from the
    # Open Group Base Specifications Portable Filename Character Set:
    # http://pubs.opengroup.org/onlinepubs/9699919799/
    for (i=1; i<=26; i++) {
        PFCS[i] = sprintf("%c", i+64)
        PFCS[i+26] = sprintf("%c", i+96)
    }
    for (i=1; i<=10; i++) {
        PFCS[i+52] = sprintf("%c", i+47)
    }
    PFCS[63] = "."
    PFCS[64] = "_"
    PFCS[65] = "-"
    PFCS_LEN = 65

    # Since we cannot know why making a file fails, we have to set a
    # limit on the maximum number of attempts and just try for a bit.
    # 100 is actually quite a lot, but we should only have this on
    # error conditions, which should be rare.
    MKDTEMP_MAX_TRIES = 100

    # seed our random number generator (not all awk do this by default)
    srand()
}

# Create a temporary directory.
#
# parameters:
# * template: a string ending with "XXXXXX", which will become the
#             directory name
#
# returns: "" on error, otherwise the new directory name
function mkdtemp(template) {
    # if the template does not end with "XXXXXX" then it is an error
    if (template !~ /XXXXXX$/) {
        return ""
    } 
    # remove the 6 X characters at the end
    base_template = substr(template, 1, length(template)-6)
    # loop until we successfully create a unique directory
    cnt = 0
    do {
        # if we have too many attempts, return an error
        if (++cnt >= MKDTEMP_MAX_TRIES) {
            return ""
        }
        # create our unique suffix by adding random characters
        uniq_suffix = ""
        for (i=0; i<6; i++) {
            uniq_suffix = uniq_suffix PFCS[int(rand() * PFCS_LEN) + 1]
        }
        # add the suffix to the base name in the template
        dirname = base_template uniq_suffix
    # use the POSIX-standard mkdir command to make the directory
    } while (system("mkdir -m 0700 " dirname " >/dev/null 2>&1") != 0);
    return dirname
}
