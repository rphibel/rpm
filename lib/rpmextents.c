
#include "system.h"

#include <rpm/rpmlog.h>
#include <rpm/rpmio.h>

#include "lib/rpmextents_internal.h"

rpmRC isTranscodedRpm(FD_t fd) {
    rpmRC rc = RPMRC_NOTFOUND;
    rpm_loff_t current;
    extents_magic_t magic;
    size_t len;

    // If the file is not seekable, we cannot detect whether or not it is transcoded.
    if(Fseek(fd, 0, SEEK_CUR) < 0) {
        return RPMRC_FAIL;
    }
    current = Ftell(fd);

    if(Fseek(fd, -(sizeof(magic)), SEEK_END) < 0) {
	rpmlog(RPMLOG_ERR, _("isTranscodedRpm: failed to seek for magic\n"));
	rc = RPMRC_FAIL;
	goto exit;
    }
    len = sizeof(magic);
    if (Fread(&magic, len, 1, fd) != len) {
	rpmlog(RPMLOG_ERR, _("isTranscodedRpm: unable to read magic\n"));
	rc = RPMRC_FAIL;
	goto exit;
    }
    if (magic != EXTENTS_MAGIC) {
	rpmlog(RPMLOG_DEBUG, _("isTranscodedRpm: not transcoded\n"));
	rc = RPMRC_NOTFOUND;
	goto exit;
    }
    rc = RPMRC_OK;
exit:
    if (Fseek(fd, current, SEEK_SET) < 0) {
	rpmlog(RPMLOG_ERR, _("isTranscodedRpm: unable to seek back to original location\n"));
	rc = RPMRC_FAIL;
    }
    return rc;
}


