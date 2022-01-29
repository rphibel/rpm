/* rpm2extents: convert payload to inline extents */

#include "system.h"

#include <rpm/rpmcli.h>
#include <rpm/rpmlib.h>		/* rpmReadPackageFile .. */
#include <rpm/rpmlog.h>
#include <rpm/rpmfi.h>
#include <rpm/rpmtag.h>
#include <rpm/rpmio.h>
#include <rpm/rpmpgp.h>

#include <rpm/rpmts.h>
#include "lib/rpmlead.h"
#include "lib/rpmts.h"
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

/* magic value at end of file (64 bits) that indicates this is a transcoded
 * rpm.
 */
#define MAGIC 3472329499408095051

struct digestoffset {
    const unsigned char * digest;
    rpm_loff_t pos;
};

rpm_loff_t pad_to(rpm_loff_t pos, rpm_loff_t unit);

rpm_loff_t pad_to(rpm_loff_t pos, rpm_loff_t unit)
{
    return (unit - (pos % unit)) % unit;
}

static struct poptOption optionsTable[] = {
    { NULL, '\0', POPT_ARG_INCLUDE_TABLE, rpmcliAllPoptTable, 0,
    N_("Common options for all rpm modes and executables:"), NULL },

    POPT_AUTOALIAS
    POPT_AUTOHELP
    POPT_TABLEEND
};


static int digestor(
    FD_t fdi,
    FD_t fdo,
    FD_t validationo,
    uint8_t algos[],
    uint32_t algos_len
)
{
    ssize_t fdilength;
    const char *filedigest, *algo_name;
    size_t filedigest_len, len;
    uint32_t algo_name_len, algo_digest_len;
    int algo;
    rpmRC rc = RPMRC_FAIL;

    for (algo = 0; algo < algos_len; algo++) {
	fdInitDigest(fdi, algos[algo], 0);
    }
    fdilength = ufdCopy(fdi, fdo);
    if (fdilength == -1) {
	fprintf(stderr, _("digest cat failed\n"));
	goto exit;
    }

    len = sizeof(fdilength);
    if (Fwrite(&fdilength, len, 1, validationo) != len) {
	fprintf(stderr, _("Unable to write input length %zd\n"), fdilength);
	goto exit;
    }
    len = sizeof(algos_len);
    if (Fwrite(&algos_len, len, 1, validationo) != len) {
	fprintf(stderr, _("Unable to write number of validation digests\n"));
	goto exit;
    }
    for (algo = 0; algo < algos_len; algo++) {
	fdFiniDigest(fdi, algos[algo], (void **)&filedigest, &filedigest_len, 0);

	algo_name = pgpValString(PGPVAL_HASHALGO, algos[algo]);
	algo_name_len = (uint32_t)strlen(algo_name);
	algo_digest_len = (uint32_t)filedigest_len;

	len = sizeof(algo_name_len);
	if (Fwrite(&algo_name_len, len, 1, validationo) != len) {
	    fprintf(stderr,
		    _("Unable to write validation algo name length\n"));
	    goto exit;
	}
	len = sizeof(algo_digest_len);
	if (Fwrite(&algo_digest_len, len, 1, validationo) != len) {
	    fprintf(stderr,
		    _("Unable to write number of bytes for validation digest\n"));
	     goto exit;
	}
	if (Fwrite(algo_name, algo_name_len, 1, validationo) != algo_name_len) {
	    fprintf(stderr, _("Unable to write validation algo name\n"));
	    goto exit;
	}
	if (Fwrite(filedigest, algo_digest_len, 1, validationo ) != algo_digest_len) {
	    fprintf(stderr,
		    _("Unable to write validation digest value %u, %zu\n"),
		    algo_digest_len, filedigest_len);
	    goto exit;
	}
    }
    rc = RPMRC_OK;
exit:
    return rc;
}

static rpmRC validator(FD_t fdi, FD_t fdo){
    int rc;
    char *msg = NULL;
    rpmts ts = rpmtsCreate();
    size_t len;

    rpmtsSetRootDir(ts, rpmcliRootDir);
    rc = rpmcliVerifySignaturesFD(ts, fdi, &msg);
    if(rc){
	fprintf(stderr, _("Error validating package\n"));
    }
    len = sizeof(rc);
    if (Fwrite(&rc, len, 1, fdo) != len) {
	fprintf(stderr, _("Unable to write validator RC code %d\n"), rc);
	goto exit;
    }
    size_t validator_len = msg ? strlen(msg) : 0;
    len = sizeof(validator_len);
    if (Fwrite(&validator_len, len, 1, fdo) != len) {
	fprintf(stderr, _("Unable to write validator output length code %zd\n"), validator_len);
	goto exit;
    }
    if (Fwrite(msg, validator_len, 1, fdo) != validator_len) {
	fprintf(stderr, _("Unable to write validator output %s\n"), msg);
	goto exit;
    }

exit:
    if(msg) {
	free(msg);
    }
    return rc ? RPMRC_FAIL : RPMRC_OK;
}

static rpmRC process_package(FD_t fdi, FD_t digestori, FD_t validationi)
{
    uint32_t diglen;
    /* GNU C extension: can use diglen from outer context */
    int digestSetCmp(const unsigned char * a, const unsigned char * b) {
	return memcmp(a, b, diglen);
    }

    unsigned int digestSetHash(const unsigned char * digest) {
        /* assumes sizeof(unsigned int) < diglen */
        return *(unsigned int *)digest;
    }

    int digestoffsetCmp(const void * a, const void * b) {
	return digestSetCmp(
	    ((struct digestoffset *)a)->digest,
	    ((struct digestoffset *)b)->digest
	);
    }

    FD_t fdo;
    FD_t gzdi;
    Header h, sigh;
    long fundamental_block_size = sysconf(_SC_PAGESIZE);
    rpmRC rc = RPMRC_OK;
    rpm_mode_t mode;
    char *rpmio_flags = NULL, *zeros;
    const unsigned char *digest;
    rpm_loff_t pos, size, pad, digest_pos, validation_pos, digest_table_pos;
    uint32_t offset_ix = 0;
    size_t len;
    int next = 0;

    fdo = fdDup(STDOUT_FILENO);

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

    /* Retrieve payload size and compression type. */
    {
	const char *compr = headerGetString(h, RPMTAG_PAYLOADCOMPRESSOR);
	rpmio_flags = rstrscat(NULL, "r.", compr ? compr : "gzip", NULL);
    }

    gzdi = Fdopen(fdi, rpmio_flags);	/* XXX gzdi == fdi */
    free(rpmio_flags);

    if (gzdi == NULL) {
	fprintf(stderr, _("cannot re-open payload: %s\n"), Fstrerror(gzdi));
	exit(EXIT_FAILURE);
    }

    rpmfiles files = rpmfilesNew(NULL, h, 0, RPMFI_KEEPHEADER);
    rpmfi fi = rpmfiNewArchiveReader(gzdi, files,
				     RPMFI_ITER_READ_ARCHIVE_CONTENT_FIRST);

    /* this is encoded in the file format, so needs to be fixed size (for
     * now?)
     */
    diglen = (uint32_t)rpmDigestLength(rpmfiDigestAlgo(fi));
    digestSet ds = digestSetCreate(rpmfiFC(fi), digestSetHash, digestSetCmp,
				   NULL);
    struct digestoffset offsets[rpmfiFC(fi)];
    pos = RPMLEAD_SIZE + headerSizeof(sigh, HEADER_MAGIC_YES);

    /* main headers are aligned to 8 byte boundry */
    pos += pad_to(pos, 8);
    pos += headerSizeof(h, HEADER_MAGIC_YES);

    zeros = xcalloc(fundamental_block_size, 1);

    while (next >= 0) {
	next = rpmfiNext(fi);
	if (next == RPMERR_ITER_END) {
	    rc = RPMRC_OK;
	    break;
	}
	mode = rpmfiFMode(fi);
	if (!S_ISREG(mode) || !rpmfiArchiveHasContent(fi)) {
	    /* not a regular file, or the archive doesn't contain any content
	     * for this entry.
	    */
	    continue;
	}
	digest = rpmfiFDigest(fi, NULL, NULL);
	if (digestSetGetEntry(ds, digest, NULL)) {
	    /* This specific digest has already been included, so skip it. */
	    continue;
	}
	pad = pad_to(pos, fundamental_block_size);
	if (Fwrite(zeros, sizeof(char), pad, fdo) != pad) {
	    fprintf(stderr, _("Unable to write padding\n"));
	    rc = RPMRC_FAIL;
	    goto exit;
	}
	/* round up to next fundamental_block_size */
	pos += pad;
	digestSetAddEntry(ds, digest);
	offsets[offset_ix].digest = digest;
	offsets[offset_ix].pos = pos;
	offset_ix++;
	size = rpmfiFSize(fi);
	rc = rpmfiArchiveReadToFile(fi, fdo, 0);
	if (rc != RPMRC_OK) {
	    fprintf(stderr, _("rpmfiArchiveReadToFile failed with %d\n"), rc);
	    goto exit;
	}
	pos += size;
    }
    Fclose(gzdi);	/* XXX gzdi == fdi */

    qsort(offsets, (size_t)offset_ix, sizeof(struct digestoffset),
	  digestoffsetCmp);

    validation_pos = pos;
    ssize_t validation_len = ufdCopy(validationi, fdo);
    if (validation_len == -1) {
	fprintf(stderr, _("validation output ufdCopy failed\n"));
	rc = RPMRC_FAIL;
	goto exit;
    }

    digest_table_pos = validation_pos + validation_len;

    len = sizeof(offset_ix);
    if (Fwrite(&offset_ix, len, 1, fdo) != len) {
	fprintf(stderr, _("Unable to write length of table\n"));
	rc = RPMRC_FAIL;
	goto exit;
    }
    len = sizeof(diglen);
    if (Fwrite(&diglen, len, 1, fdo) != len) {
	fprintf(stderr, _("Unable to write length of digest\n"));
	rc = RPMRC_FAIL;
	goto exit;
    }
    len = sizeof(rpm_loff_t);
    for (int x = 0; x < offset_ix; x++) {
	if (Fwrite(offsets[x].digest, diglen, 1, fdo) != diglen) {
	    fprintf(stderr, _("Unable to write digest\n"));
	    rc = RPMRC_FAIL;
	    goto exit;
	}
	if (Fwrite(&offsets[x].pos, len, 1, fdo) != len) {
	    fprintf(stderr, _("Unable to write offset\n"));
	    rc = RPMRC_FAIL;
	    goto exit;
	}
    }
    digest_pos = (
	digest_table_pos + sizeof(offset_ix) + sizeof(diglen) +
	offset_ix * (diglen + sizeof(rpm_loff_t))
    );

    ssize_t digest_len = ufdCopy(digestori, fdo);
    if (digest_len == -1) {
	fprintf(stderr, _("digest table ufdCopy failed\n"));
	rc = RPMRC_FAIL;
	goto exit;
    }

    /* add more padding so the last file can be cloned. It doesn't matter that
     * the table and validation etc are in this space. In fact, it's pretty
     * efficient if it is.
    */

    pad = pad_to((validation_pos + validation_len + 2 * sizeof(rpm_loff_t) +
		 sizeof(uint64_t)), fundamental_block_size);
    if (Fwrite(zeros, sizeof(char), pad, fdo) != pad) {
	fprintf(stderr, _("Unable to write final padding\n"));
	rc = RPMRC_FAIL;
	goto exit;
    }
    zeros = _free(zeros);
    if (Fwrite(&validation_pos, len, 1, fdo) != len) {
	fprintf(stderr, _("Unable to write offset of validation output\n"));
	rc = RPMRC_FAIL;
	goto exit;
    }
    if (Fwrite(&digest_table_pos, len, 1, fdo) != len) {
	fprintf(stderr, _("Unable to write offset of digest table\n"));
	rc = RPMRC_FAIL;
	goto exit;
    }
    if (Fwrite(&digest_pos, len, 1, fdo) != len) {
	fprintf(stderr, _("Unable to write offset of validation table\n"));
	rc = RPMRC_FAIL;
	goto exit;
    }
    uint64_t magic = MAGIC;
    len = sizeof(magic);
    if (Fwrite(&magic, len, 1, fdo) != len) {
	fprintf(stderr, _("Unable to write magic\n"));
	rc = RPMRC_FAIL;
	goto exit;
    }

exit:
    rpmfilesFree(files);
    rpmfiFree(fi);
    headerFree(h);
    return rc;
}

static off_t ufdTee(FD_t sfd, FD_t *fds, int len)
{
    char buf[BUFSIZ];
    ssize_t rdbytes, wrbytes;
    off_t total = 0;

    while (1) {
	rdbytes = Fread(buf, sizeof(buf[0]), sizeof(buf), sfd);

	if (rdbytes > 0) {
	    for(int i=0; i < len; i++) {
		wrbytes = Fwrite(buf, sizeof(buf[0]), rdbytes, fds[i]);
		if (wrbytes != rdbytes) {
		    fprintf(stderr, "Error wriing to FD %d: %s\n", i, Fstrerror(fds[i]));
		    total = -1;
		    break;
		}
	    }
	    if(total == -1){
		break;
	    }
	    total += wrbytes;
	} else {
	    if (rdbytes < 0)
		total = -1;
	    break;
	}
    }

    return total;
}

static int teeRpm(FD_t fdi, FD_t digestori) {
    rpmRC rc;
    off_t offt = -1;
    int processorpipefd[2];
    int validatorpipefd[2];
    int rpmsignpipefd[2];
    pid_t cpids[2], w;
    int wstatus;
    FD_t fds[2];

     if (pipe(processorpipefd) == -1) {
	fprintf(stderr, _("Processor pipe failure\n"));
	return RPMRC_FAIL;
    }

    if (pipe(validatorpipefd) == -1) {
	fprintf(stderr, _("Validator pipe failure\n"));
	return RPMRC_FAIL;
    }

    if (pipe(rpmsignpipefd) == -1) {
	fprintf(stderr, _("Validator pipe failure\n"));
	return RPMRC_FAIL;
    }

    cpids[0] = fork();
    if (cpids[0] == 0) {
	/* child: validator */
	close(processorpipefd[0]);
	close(processorpipefd[1]);
	close(validatorpipefd[1]);
	close(rpmsignpipefd[0]);
	FD_t fdi = fdDup(validatorpipefd[0]);
	FD_t fdo = fdDup(rpmsignpipefd[1]);
	close(rpmsignpipefd[1]);
	rc = validator(fdi, fdo);
	if(rc != RPMRC_OK) {
	    fprintf(stderr, _("Validator failed\n"));
	}
	Fclose(fdi);
	Fclose(fdo);
	if (rc != RPMRC_OK) {
	    exit(EXIT_FAILURE);
	}
	exit(EXIT_SUCCESS);
    } else {
	/* parent: main program */
	cpids[1] = fork();
	if (cpids[1] == 0) {
	    /* child: process_package */
	    close(validatorpipefd[0]);
	    close(validatorpipefd[1]);
	    close(processorpipefd[1]);
	    close(rpmsignpipefd[1]);
	    FD_t fdi = fdDup(processorpipefd[0]);
	    close(processorpipefd[0]);
	    FD_t validatori = fdDup(rpmsignpipefd[0]);
	    close(rpmsignpipefd[0]);

	    rc = process_package(fdi, digestori, validatori);
	    if(rc != RPMRC_OK) {
		fprintf(stderr, _("Validator failed\n"));
	    }
	    Fclose(digestori);
	    Fclose(validatori);
	    /* fdi is normally closed through the stacked file gzdi in the
	     * function
	     */

	    if (rc != RPMRC_OK) {
		exit(EXIT_FAILURE);
	    }
	    exit(EXIT_SUCCESS);


	} else {
	    /* Actual parent. Read from fdi and write to both processes */
	    close(processorpipefd[0]);
	    close(validatorpipefd[0]);
	    fds[0] = fdDup(processorpipefd[1]);
	    fds[1] = fdDup(validatorpipefd[1]);
	    close(validatorpipefd[1]);
	    close(processorpipefd[1]);
	    close(rpmsignpipefd[0]);
	    close(rpmsignpipefd[1]);

	    rc = RPMRC_OK;
	    offt = ufdTee(fdi, fds, 2);
	    if(offt == -1){
		fprintf(stderr, _("Failed to tee RPM\n"));
		rc = RPMRC_FAIL;
	    }
	    Fclose(fds[0]);
	    Fclose(fds[1]);
	    w = waitpid(cpids[0], &wstatus, 0);
	    if (w == -1) {
		fprintf(stderr, _("waitpid cpids[0] failed\n"));
		rc = RPMRC_FAIL;
	    }
	    w = waitpid(cpids[1], &wstatus, 0);
	    if (w == -1) {
		fprintf(stderr, _("waitpid cpids[1] failed\n"));
		rc = RPMRC_FAIL;
	    }
	}
    }

    return rc;
}

int main(int argc, char *argv[]) {
    rpmRC rc;
    int cprc = 0;
    poptContext optCon = NULL;
    const char **args = NULL;
    int nb_algos = 0;

    int mainpipefd[2];
    int metapipefd[2];
    pid_t cpid, w;
    int wstatus;

    xsetprogname(argv[0]);	/* Portability call -- see system.h */
    rpmReadConfigFiles(NULL, NULL);
    optCon = rpmcliInit(argc, argv, optionsTable);
    poptSetOtherOptionHelp(optCon, "[OPTIONS]* <DIGESTALGO>");

    if (poptPeekArg(optCon) == NULL) {
	fprintf(stderr,
		_("Need at least one DIGESTALGO parameter, e.g. 'SHA256'\n"));
	poptPrintUsage(optCon, stderr, 0);
	exit(EXIT_FAILURE);
    }

    args = poptGetArgs(optCon);

    for (nb_algos=0; args[nb_algos]; nb_algos++);
    uint8_t algos[nb_algos];
    for (int x = 0; x < nb_algos; x++) {
	if (pgpStringVal(PGPVAL_HASHALGO, args[x], &algos[x]) != 0)
	{
	    fprintf(stderr,
		    _("Unable to resolve '%s' as a digest algorithm, exiting\n"),
		    args[x]);
	    exit(EXIT_FAILURE);
	}
    }

    if (pipe(mainpipefd) == -1) {
	fprintf(stderr, _("Main pipe failure\n"));
	exit(EXIT_FAILURE);
    }
    if (pipe(metapipefd) == -1) {
	fprintf(stderr, _("Meta pipe failure\n"));
	exit(EXIT_FAILURE);
    }

    cpid = fork();
    if (cpid == 0) {
	/* child: digestor */
	close(mainpipefd[0]);
	close(metapipefd[0]);
	FD_t fdi = fdDup(STDIN_FILENO);
	FD_t fdo = fdDup(mainpipefd[1]);
	FD_t validationo = fdDup(metapipefd[1]);
	rc = digestor(fdi, fdo, validationo, algos, nb_algos);
	Fclose(validationo);
	Fclose(fdo);
	Fclose(fdi);
    } else {
	/* parent: main program */
	close(mainpipefd[1]);
	close(metapipefd[1]);
	FD_t fdi = fdDup(mainpipefd[0]);
	FD_t digestori = fdDup(metapipefd[0]);
	rc = teeRpm(fdi, digestori);
	Fclose(digestori);
	/* Wait for child process (digestor for stdin) to complete.
	 */
	if (rc != RPMRC_OK) {
	    if (kill(cpid, SIGTERM) != 0) {
		fprintf(stderr,
		        _("Failed to kill digest process when main process failed: %s\n"),
			strerror(errno));
	    }
	}
	w = waitpid(cpid, &wstatus, 0);
	if (w == -1) {
	    fprintf(stderr, _("waitpid %d failed %s\n"), cpid, strerror(errno));
	    cprc = EXIT_FAILURE;
	} else if (WIFEXITED(wstatus)) {
	    cprc = WEXITSTATUS(wstatus);
	    if (cprc != 0) {
		fprintf(stderr,
			_("Digest process non-zero exit code %d\n"),
			cprc);
	    }
	} else if (WIFSIGNALED(wstatus)) {
	    fprintf(stderr,
		    _("Digest process was terminated with a signal: %d\n"),
		    WTERMSIG(wstatus));
	    cprc = EXIT_FAILURE;
	} else {
	    /* Don't think this can happen, but covering all bases */
	    fprintf(stderr, _("Unhandled circumstance in waitpid\n"));
	    cprc = EXIT_FAILURE;
	}
	if (cprc != EXIT_SUCCESS) {
	    rc = RPMRC_FAIL;
	}
    }
    if (rc != RPMRC_OK) {
	/* translate rpmRC into generic failure return code. */
	return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
