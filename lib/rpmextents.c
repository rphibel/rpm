
#include "system.h"

#include <rpm/rpmlog.h>
#include <rpm/rpmio.h>
#include <string.h>
#include <errno.h>


#include "lib/rpmextents_internal.h"

rpmRC extentsFooterFromFD(FD_t fd, struct extents_footer_t *footer) {

    rpmRC rc = RPMRC_NOTFOUND;
    rpm_loff_t current;
    size_t len;

    // If the file is not seekable, we cannot detect whether or not it is transcoded.
    if(Fseek(fd, 0, SEEK_CUR) < 0) {
        return RPMRC_FAIL;
    }
    current = Ftell(fd);

    len = sizeof(struct extents_footer_t);
    if(Fseek(fd, -len, SEEK_END) < 0) {
	rpmlog(RPMLOG_ERR, _("isTranscodedRpm: failed to seek for footer: %s\n"), strerror(errno));
	rc = RPMRC_FAIL;
	goto exit;
    }
    if (Fread(footer, len, 1, fd) != len) {
	rpmlog(RPMLOG_ERR, _("isTranscodedRpm: unable to read footer\n"));
	rc = RPMRC_FAIL;
	goto exit;
    }
    if (footer->magic != EXTENTS_MAGIC) {
	rpmlog(RPMLOG_ERR, _("isTranscodedRpm: not transcoded\n"));
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

rpmRC isTranscodedRpm(FD_t fd) {
    struct extents_footer_t footer;
    return extentsFooterFromFD(fd, &footer);
}


