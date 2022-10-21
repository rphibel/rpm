/* rpm2extents: convert payload to inline extents */

#include "system.h"

#include <rpm/rpmlib.h>		/* rpmReadPackageFile .. */
#include <rpm/rpmfi.h>
#include <rpm/rpmtag.h>
#include <rpm/rpmio.h>
#include <rpm/rpmpgp.h>

#include <rpm/rpmts.h>
#include "lib/rpmlead.h"
#include "lib/signature.h"
#include "lib/header_internal.h"
#include "rpmio/rpmio_internal.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <string.h>

#include "debug.h"

/* hash of void * (pointers) to file digests to offsets within output.
 * The length of the key depends on what the FILEDIGESTALGO is.
 */
#undef HASHTYPE
#undef HTKEYTYPE
#undef HTDATATYPE
#define HASHTYPE digestSet
#define HTKEYTYPE const unsigned char *
#include "lib/rpmhash.H"
#include "lib/rpmhash.C"

static rpmRC process_package(FD_t fdi, FD_t fdo)
{
    Header h, sigh;
    rpmRC rc = RPMRC_OK;

    if (rpmReadPackageRaw(fdi, &sigh, &h)) {
	fprintf(stderr, _("Error reading package\n"));
	exit(EXIT_FAILURE);
    }

    if (rpmLeadWrite(fdo, h))
    {
	fprintf(stderr, _("Unable to write package lead: %s\n"),
		Fstrerror(fdo));
	exit(EXIT_FAILURE);
    }

    if (rpmWriteSignature(fdo, sigh)) {
	fprintf(stderr, _("Unable to write signature: %s\n"), Fstrerror(fdo));
	exit(EXIT_FAILURE);
    }

    if (headerWrite(fdo, h, HEADER_MAGIC_YES)) {
	fprintf(stderr, _("Unable to write headers: %s\n"), Fstrerror(fdo));
	exit(EXIT_FAILURE);
    }

	ssize_t fdilength = ufdCopy(fdi, fdo);
	if (fdilength == -1) {
		fprintf(stderr, _("process_package cat failed\n"));
		rc = RPMRC_FAIL;
	}

exit:
    headerFree(sigh);
    headerFree(h);
    return rc;
}

int main(int argc, char *argv[]) {
    rpmRC rc;
    int cprc = 0;
    uint8_t algos[argc - 1];
    int mainpipefd[2];
    int metapipefd[2];
    pid_t cpid, w;
    int wstatus;

    xsetprogname(argv[0]);	/* Portability call -- see system.h */
    rpmReadConfigFiles(NULL, NULL);

	FD_t fdi = fdDup(STDIN_FILENO);
    FD_t fdo = fdDup(STDOUT_FILENO);
	rc = process_package(fdi, fdo);

    if (rc != RPMRC_OK) {
	/* translate rpmRC into generic failure return code. */
	return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
