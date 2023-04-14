#include "system.h"

#include <errno.h>
#include <sys/resource.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#if defined(__linux__)
#include <linux/fs.h>        /* For FICLONE */
#endif

#include <rpm/rpmlog.h>
#include <rpm/rpmlib.h>
#include "lib/rpmplugin.h"
#include "rpmextents_internal.h"
#include "lib/rpmte_internal.h"
#include <rpm/rpmfileutil.h>
#include "rpmio/rpmio_internal.h"
#include "lib/fsm.h"


#include "debug.h"

#include <sys/ioctl.h>

/* use hash table to remember inode -> ix (for rpmfilesFN(ix)) lookups */
#undef HASHTYPE
#undef HTKEYTYPE
#undef HTDATATYPE
#define HASHTYPE inodeIndexHash
#define HTKEYTYPE rpm_ino_t
#define HTDATATYPE const char *
#include "lib/rpmhash.H"
#include "lib/rpmhash.C"

/* We use this in find to indicate a key wasn't found. This is an
 * unrecoverable error, but we can at least show a decent error. 0 is never a
 * valid offset because it's the offset of the start of the file.
 */
#define NOT_FOUND 0

#define BUFFER_SIZE (1024 * 128)

#define RPMRC_PLUGIN_CONTENTS 5

struct reflink_state_s {
    /* Stuff that's used across rpms */
    long fundamental_block_size;
    char *buffer;

    /* stuff that's used/updated per psm */
    uint32_t keys, keysize;

    /* table for current rpm, keys * (keysize + sizeof(rpm_loff_t)) */
    unsigned char *table;
    FD_t fd;
    rpmfiles files;
    inodeIndexHash inodeIndexes;
    int transcoded;
};

typedef struct reflink_state_s * reflink_state;

static rpmfi reflink_fsm_file_archive_reader(FD_t payload, rpmfiles files, int itype, rpmPlugin plugin);
static int reflink_fsm_file_install(rpmte te, rpmfi fi, filedata fp, rpmfiles files, rpmpsm psm, int nodigest, filedata  *firstlink, int *firstlinkfile, diriter di, int *fdp, int rc, rpmPlugin plugin);

/*
 * bsearch_r: implements a re-entrant version of stdlib's bsearch.
 * code taken and adapted from /usr/include/bits/stdlib-bsearch.h
 */
static inline void *
bsearch_r (const void *__key, const void *__base, size_t __nmemb, size_t __size,
	 __compar_d_fn_t __compar, void *__arg)
{
  size_t __l, __u, __idx;
  const void *__p;
  int __comparison;

  __l = 0;
  __u = __nmemb;
  while (__l < __u)
    {
      __idx = (__l + __u) / 2;
      __p = (const void *) (((const char *) __base) + (__idx * __size));
      __comparison = (*__compar) (__key, __p, __arg);
      if (__comparison < 0)
	__u = __idx;
      else if (__comparison > 0)
	__l = __idx + 1;
      else
	{
#if __GNUC_PREREQ(4, 6)
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wcast-qual"
#endif
	  return (void *) __p;
#if __GNUC_PREREQ(4, 6)
# pragma GCC diagnostic pop
#endif
	}
    }

  return NULL;
}

static char *abspath(rpmfi fi, const char *path)
{
    if (*path == '/')
	return xstrdup(path);
    else
	return rstrscat(NULL, rpmfiDN(fi), path, NULL);
}

static int cmpdigest(const void *k1, const void *k2, void *data) {
    rpmlog(RPMLOG_DEBUG, _("reflink: cmpdigest k1=%p k2=%p\n"), k1, k2);
    return memcmp(k1, k2, *(int *)data);
}

static int inodeCmp(rpm_ino_t a, rpm_ino_t b)
{
    return (a != b);
}

static unsigned int inodeId(rpm_ino_t a)
{
    /* rpm_ino_t is uint32_t so maps safely to unsigned int */
    return (unsigned int)a;
}

static rpmRC reflink_init(rpmPlugin plugin, rpmts ts) {
    reflink_state state = rcalloc(1, sizeof(struct reflink_state_s));

    /* IOCTL-FICLONERANGE(2): ...Disk filesystems generally require the offset
     * and length arguments to be aligned to the fundamental block size.
     *
     * The value of "fundamental block size" is directly related to the
     * system's page size, so we should use that.
     */
    state->fundamental_block_size = sysconf(_SC_PAGESIZE);
    state->buffer = rcalloc(1, BUFFER_SIZE);
    rpmPluginSetData(plugin, state);

    return RPMRC_OK;
}

static void reflink_cleanup(rpmPlugin plugin) {
    reflink_state state = rpmPluginGetData(plugin);
    free(state->buffer);
    free(state);
}

static int reflink_verifyPackageFile(FD_t fd, rpmts ts, rpmte p, rpmvs vs, vfydata pvd, int *pverified) {
    rpmRC prc = RPMRC_FAIL;
    if(fd != NULL && isTranscodedRpm(fd) == RPMRC_OK) {
	/* Transcoded RPMs are validated at transcoding time */
	prc = extentsVerifySigs(fd, 0);
	*pverified = prc == RPMRC_OK;
    }
    return prc;
}

static rpmRC reflink_content_handler(rpmPlugin plugin, rpmte te, rpmPluginContentHandler handler) {
    rpmRC rc;
    size_t len;
    FD_t fd = NULL;

    reflink_state state = rpmPluginGetData(plugin);

    const char * filename = (const char *)rpmteKey(te);
    if (filename == NULL || filename[0] == '\0') {
	rpmlog(RPMLOG_ERR, _("empty filename\n"));
	rc = RPMRC_FAIL;
	goto exit;
    }

    fd = Fopen(filename, "r.ufdio");
    if (fd == NULL || Ferror(fd)) {
	rpmlog(RPMLOG_ERR, _("open of %s failed: %s\n"), filename,
	    Fstrerror(fd));
	rc = RPMRC_FAIL;
	goto exit;
    }

    rc = isTranscodedRpm(fd);

    switch(rc){
	// Fail to parse the file, fail the plugin.
	case RPMRC_FAIL:
	    rc = RPMRC_FAIL;
	    goto exit;
	// This is not a transcoded file, do nothing.
	case RPMRC_NOTFOUND:
	    rc = RPMRC_OK;
	    goto exit;
	default:
	    break;
    }
    rpmlog(RPMLOG_DEBUG, _("reflink: *is* transcoded\n"));
    state->transcoded = 1;
    handler->archiveReader = reflink_fsm_file_archive_reader;
    handler->fileInstall = reflink_fsm_file_install;
    handler->verify = reflink_verifyPackageFile;

    state->files = rpmteFiles(te);
    /* tail of file contains offset_table, offset_checksums then magic */
    if (Fseek(fd, -(sizeof(rpm_loff_t) * 2 + sizeof(extents_magic_t)), SEEK_END) < 0) {
	rpmlog(RPMLOG_ERR, _("reflink: failed to seek for tail %p\n"),
	       fd);
	rc = RPMRC_FAIL;
	goto exit;
    }
    rpm_loff_t table_start;
    len = sizeof(table_start);
    if (Fread(&table_start, len, 1, fd) != len) {
	rpmlog(RPMLOG_ERR, _("reflink: unable to read table_start\n"));
	rc = RPMRC_FAIL;
	goto exit;
    }
    if (Fseek(fd, table_start, SEEK_SET) < 0) {
	rpmlog(RPMLOG_ERR, _("reflink: unable to seek to table_start\n"));
	rc = RPMRC_FAIL;
	goto exit;
    }
    len = sizeof(state->keys);
    if (Fread(&state->keys, len, 1, fd) != len) {
	rpmlog(RPMLOG_ERR, _("reflink: unable to read number of keys\n"));
	rc = RPMRC_FAIL;
	goto exit;
    }
    len = sizeof(state->keysize);
    if (Fread(&state->keysize, len, 1, fd) != len) {
	rpmlog(RPMLOG_ERR, _("reflink: unable to read keysize\n"));
	rc = RPMRC_FAIL;
	goto exit;
    }
    rpmlog(
	RPMLOG_DEBUG,
	_("reflink: table_start=0x%lx, keys=%d, keysize=%d\n"),
	table_start, state->keys, state->keysize
    );
    /* now get digest table if there is a reason to have one. */
    if (state->keys == 0 || state->keysize == 0) {
	/* no files (or no digests(!)) */
	state->table = NULL;
    } else {
	int table_size = state->keys * (state->keysize + sizeof(rpm_loff_t));
	state->table = rcalloc(1, table_size);
	if (Fread(state->table, table_size, 1, fd) != table_size) {
	    rpmlog(RPMLOG_ERR, _("reflink: unable to read table\n"));
	    rc = RPMRC_FAIL;
	    goto exit;
	}
	state->inodeIndexes = inodeIndexHashCreate(
	    state->keys, inodeId, inodeCmp, NULL, (inodeIndexHashFreeData)rfree
	);
    }

    rc = RPMRC_OK;

exit:
    if (fd != NULL) {
	Fclose(fd);
	fd = NULL;
    }	
    return rc;
}

static rpmRC reflink_psm_post(rpmPlugin plugin, rpmte te, int res)
{
    reflink_state state = rpmPluginGetData(plugin);
    state->files = rpmfilesFree(state->files);
    if (state->table) {
	free(state->table);
	state->table = NULL;
    }
    if (state->inodeIndexes) {
	inodeIndexHashFree(state->inodeIndexes);
	state->inodeIndexes = NULL;
    }
    return RPMRC_OK;
}


/* have a prototype, warnings system */
rpm_loff_t find(const unsigned char *digest, reflink_state state);

rpm_loff_t find(const unsigned char *digest, reflink_state state) {
    rpmlog(RPMLOG_DEBUG,
	   _("reflink: bsearch_r(key=%p, base=%p, nmemb=%d, size=%lu)\n"),
	   digest, state->table, state->keys,
	   state->keysize + sizeof(rpm_loff_t));
    char *entry = bsearch_r(digest, state->table, state->keys,
			    state->keysize + sizeof(rpm_loff_t), cmpdigest,
			    &state->keysize);
    if (entry == NULL) {
	return NOT_FOUND;
    }
    rpm_loff_t offset = *(rpm_loff_t *)(entry + state->keysize);
    return offset;
}

static int reflink_fsm_file_install(rpmte te, rpmfi fi, filedata fp, rpmfiles files, rpmpsm psm, int nodigest, filedata  *firstlink, int *firstlinkfile, diriter di, int *fdp, int rc, rpmPlugin plugin)
{
    struct file_clone_range fcr;
    rpm_loff_t size;
    int dst;
    const char **hl_target = NULL;
    char *apath = abspath(fi, fp->fpath);

    reflink_state state = rpmPluginGetData(plugin);
    if (state->table == NULL) {
	/* no table means rpm is not in reflink format, so leave. Now. */
	rc = fsmFileInstall(te, fi, fp, files, psm,  nodigest, firstlink, firstlinkfile, di, fdp, rc, NULL);
	goto exit;
    }
    if (fp->action == FA_TOUCH) {
	/* we're not overwriting an existing file. */
	rc = fsmFileInstall(te, fi, fp, files, psm,  nodigest, firstlink, firstlinkfile, di, fdp, rc, NULL);
	goto exit;
    }
    fcr.dest_offset = 0;
    if (S_ISREG(fp->sb.st_mode) && !(rpmfiFFlags(fi) & RPMFILE_GHOST)) {
	rpm_ino_t inode = rpmfiFInode(fi);
	/* check for hard link entry in table. GetEntry overwrites hlix with
	 * the address of the first match.
	 */
	if (inodeIndexHashGetEntry(state->inodeIndexes, inode, &hl_target,
				   NULL, NULL)) {
	    /* entry is in table, use hard link */
	    if (link(hl_target[0], apath) != 0) {
		rpmlog(RPMLOG_ERR,
		       _("reflink: Unable to hard link %s -> %s due to %s\n"),
		       hl_target[0], apath, strerror(errno));
		rc = RPMRC_FAIL;
		goto exit;
	    }
	    rc = RPMRC_OK;
	    goto exit;
	}
	/* if we didn't hard link, then we'll track this inode as being
	 * created soon
	 */
	if (rpmfiFNlink(fi) > 1) {
	    /* minor optimization: only store files with more than one link */
	    inodeIndexHashAddEntry(state->inodeIndexes, inode, rstrdup(apath));
	}
	/* derived from wfd_open in fsm.c */
	mode_t old_umask = umask(0577);
	dst = open(apath, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR);
	umask(old_umask);
	if (dst == -1) {
	    rpmlog(RPMLOG_ERR,
		   _("reflink: Unable to open %s for writing due to %s, flags = %x\n"),
		   apath, strerror(errno), rpmfiFFlags(fi));
	    rc = RPMRC_FAIL;
	    goto exit;
	}
	size = rpmfiFSize(fi);
	if (size > 0) {
	    /* round src_length down to fundamental_block_size multiple */
	    fcr.src_length = size / state->fundamental_block_size * state->fundamental_block_size;
	    if ((size % state->fundamental_block_size) > 0) {
		/* round up to next fundamental_block_size. We expect the data
		 * in the rpm to be similarly padded.
		 */
		fcr.src_length += state->fundamental_block_size;
	    }
	    fcr.src_fd = Fileno(rpmteFd(te));
	    if (fcr.src_fd == -1) {
		close(dst);
		rpmlog(RPMLOG_ERR, _("reflink: src fd lookup failed\n"));
		rc = RPMRC_FAIL;
		goto exit;
	    }
	    fcr.src_offset = find(rpmfiFDigest(fi, NULL, NULL), state);
	    if (fcr.src_offset == NOT_FOUND) {
		close(dst);
		rpmlog(RPMLOG_ERR, _("reflink: digest not found\n"));
		rc = RPMRC_FAIL;
		goto exit;
	    }
	    rpmlog(RPMLOG_DEBUG,
	           _("reflink: Reflinking %llu bytes at %llu to %s orig size=%ld, file=%lld\n"),
		   fcr.src_length, fcr.src_offset, apath, size, fcr.src_fd);
	    rc = ioctl(dst, FICLONERANGE, &fcr);
	    if (rc) {
		rpmlog(RPMLOG_WARNING,
		       _("reflink: falling back to copying bits for %s due to %d, %d = %s\n"),
		       apath, rc, errno, strerror(errno));
		if (Fseek(rpmteFd(te), fcr.src_offset, SEEK_SET) < 0) {
		    close(dst);
		    rpmlog(RPMLOG_ERR,
			   _("reflink: unable to seek on copying bits\n"));
		    rc = RPMRC_FAIL;
		    goto exit;
		}
		rpm_loff_t left = size;
		size_t len, read, written;
		while (left) {
		    len = (left > BUFFER_SIZE ? BUFFER_SIZE : left);
		    read = Fread(state->buffer, len, 1, rpmteFd(te));
		    if (read != len) {
			close(dst);
			rpmlog(RPMLOG_ERR,
			       _("reflink: short read on copying bits\n"));
			rc = RPMRC_FAIL;
			goto exit;
		    }
		    written = write(dst, state->buffer, len);
		    if (read != written) {
			close(dst);
			rpmlog(RPMLOG_ERR,
			       _("reflink: short write on copying bits\n"));
			rc = RPMRC_FAIL;
			goto exit;
		    }
		    left -= len;
		}
	    } else {
		/* reflink worked, so truncate */
		rc = ftruncate(dst, size);
		if (rc) {
		    rpmlog(RPMLOG_ERR,
			   _("reflink: Unable to truncate %s to %ld due to %s\n"),
			   apath, size, strerror(errno));
		    rc = RPMRC_FAIL;
		    goto exit;
		}
	    }
	}
	close(dst);
	rc = RPMRC_OK;
	goto exit;
    }
    rc = fsmFileInstall(te, fi, fp, files, psm,  nodigest, firstlink, firstlinkfile, di, fdp, rc, NULL);

exit:
    if (apath)
	free(apath);
    return rc;
}

static rpmfi reflink_fsm_file_archive_reader(FD_t payload, rpmfiles files, int itype, rpmPlugin plugin) {
    reflink_state state = rpmPluginGetData(plugin);
    rpmfi fi = NULL;
    if(state->transcoded) {
	fi = rpmfilesIter(files, RPMFI_ITER_FWD);
    }
    return fi;
}

struct rpmPluginHooks_s reflink_hooks = {
    .init = reflink_init,
    .cleanup = reflink_cleanup,
    .content_handler = reflink_content_handler,
    .psm_post = reflink_psm_post,
};
