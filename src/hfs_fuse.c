/*  
 * Copyright 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
#include "hfs_fuse.h"
#include "dir_tree.h"

/*{{{ struct / defines */

struct _HfsFuse {
    Application *app;
    DirTree *dir_tree;
    gchar *mountpoint;
    
    // the session that we use to process the fuse stuff
    struct fuse_session *session;
    struct fuse_chan *chan;
    // the event that we use to receive requests
    struct event *ev;
    struct event *ev_timer;
    // what our receive-message length is
    size_t recv_size;
    // the buffer that we use to receive events
    char *recv_buf;
};

#define FUSE_LOG "fuse"
/*}}}*/

/*{{{ func declarations */
static void hfs_fuse_init (void *userdata, struct fuse_conn_info *conn);
static void hfs_fuse_on_read (evutil_socket_t fd, short what, void *arg);
static void hfs_fuse_readdir (fuse_req_t req, fuse_ino_t ino, 
    size_t size, off_t off, struct fuse_file_info *fi);
static void hfs_fuse_lookup (fuse_req_t req, fuse_ino_t parent_ino, const char *name);
static void hfs_fuse_getattr (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
static void hfs_fuse_setattr (fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi);
static void hfs_fuse_open (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
static void hfs_fuse_release (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
static void hfs_fuse_read (fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi);
static void hfs_fuse_write (fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off, struct fuse_file_info *fi);
static void hfs_fuse_create (fuse_req_t req, fuse_ino_t parent_ino, const char *name, mode_t mode, struct fuse_file_info *fi);
static void hfs_fuse_forget (fuse_req_t req, fuse_ino_t ino, unsigned long nlookup);
static void hfs_fuse_unlink (fuse_req_t req, fuse_ino_t parent_ino, const char *name);
static void hfs_fuse_mkdir (fuse_req_t req, fuse_ino_t parent_ino, const char *name, mode_t mode);
static void hfs_fuse_rmdir (fuse_req_t req, fuse_ino_t parent_ino, const char *name);
static void hfs_fuse_on_timer (evutil_socket_t fd, short what, void *arg);

static struct fuse_lowlevel_ops hfs_fuse_opers = {
    .init       = hfs_fuse_init,
	.readdir	= hfs_fuse_readdir,
	.lookup		= hfs_fuse_lookup,
    .getattr	= hfs_fuse_getattr,
    .setattr	= hfs_fuse_setattr,
	.open		= hfs_fuse_open,
	.release	= hfs_fuse_release,
	.read		= hfs_fuse_read,
	.write		= hfs_fuse_write,
	.create		= hfs_fuse_create,
    .forget     = hfs_fuse_forget,
    .unlink     = hfs_fuse_unlink,
    .mkdir      = hfs_fuse_mkdir,
    .rmdir      = hfs_fuse_rmdir,
};
/*}}}*/

/*{{{ create / destroy */

// create HfsFuse object
// create fuse handle and add it to libevent polling
HfsFuse *hfs_fuse_new (Application *app, const gchar *mountpoint, const gchar *fuse_opts)
{
    HfsFuse *hfs_fuse;
    struct timeval tv;
    struct fuse_args args = FUSE_ARGS_INIT (0, NULL);

    hfs_fuse = g_new0 (HfsFuse, 1);
    hfs_fuse->app = app;
    hfs_fuse->dir_tree = application_get_dir_tree (app);
    hfs_fuse->mountpoint = g_strdup (mountpoint);

    if (fuse_opts) {
        if (fuse_opt_add_arg (&args, "hydrafs") == -1) {
            LOG_err (FUSE_LOG, "Failed to parse FUSE parameter !");
            return NULL;
        }

        if (fuse_opt_add_arg (&args, "-o") == -1) {
            LOG_err (FUSE_LOG, "Failed to parse FUSE parameter !");
            return NULL;
        }

        if (fuse_opt_add_arg (&args, fuse_opts) == -1) {
            LOG_err (FUSE_LOG, "Failed to parse FUSE parameter !");
            return NULL;
        }
    }
    
    if ((hfs_fuse->chan = fuse_mount (hfs_fuse->mountpoint, &args)) == NULL) {
        LOG_err (FUSE_LOG, "Failed to mount FUSE partition !");
        return NULL;
    }
    fuse_opt_free_args (&args);

    // the receive buffer stuff
    hfs_fuse->recv_size = fuse_chan_bufsize (hfs_fuse->chan);

    // allocate the recv buffer
    if ((hfs_fuse->recv_buf = g_malloc (hfs_fuse->recv_size)) == NULL) {
        LOG_err (FUSE_LOG, "failed to malloc memory !");
        return NULL;
    }
    
    // allocate a low-level session
    hfs_fuse->session = fuse_lowlevel_new (NULL, &hfs_fuse_opers, sizeof (hfs_fuse_opers), hfs_fuse);
    if (!hfs_fuse->session) {
        LOG_err (FUSE_LOG, "fuse_lowlevel_new");
        return NULL;
    }
    
    fuse_session_add_chan (hfs_fuse->session, hfs_fuse->chan);

    hfs_fuse->ev = event_new (application_get_evbase (app), 
        fuse_chan_fd (hfs_fuse->chan), EV_READ, &hfs_fuse_on_read, 
        hfs_fuse
    );
    if (!hfs_fuse->ev) {
        LOG_err (FUSE_LOG, "event_new");
        return NULL;
    }

    if (event_add (hfs_fuse->ev, NULL)) {
        LOG_err (FUSE_LOG, "event_add");
        return NULL;
    }
    /*
    hfs_fuse->ev_timer = evtimer_new (application_get_evbase (app), 
        &hfs_fuse_on_timer, 
        hfs_fuse
    );
    
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    LOG_err (FUSE_LOG, "event_add");
    if (event_add (hfs_fuse->ev_timer, &tv)) {
        LOG_err (FUSE_LOG, "event_add");
        return NULL;
    }
    */


    return hfs_fuse;
}

void hfs_fuse_destroy (HfsFuse *hfs_fuse)
{
    fuse_unmount (hfs_fuse->mountpoint, hfs_fuse->chan);
    g_free (hfs_fuse->mountpoint);
    g_free (hfs_fuse->recv_buf);
    event_free (hfs_fuse->ev);
    fuse_session_destroy (hfs_fuse->session);
    g_free (hfs_fuse);
}

static void hfs_fuse_on_timer (evutil_socket_t fd, short what, void *arg)
{
    struct timeval tv;
    HfsFuse *hfs_fuse = (HfsFuse *)arg;

    LOG_debug (FUSE_LOG, ">>>>>>>> On timer !!! :%d", event_pending (hfs_fuse->ev, EV_TIMEOUT|EV_READ|EV_WRITE|EV_SIGNAL, NULL));
    event_base_dump_events (application_get_evbase (hfs_fuse->app), stdout);
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    if (fuse_session_exited (hfs_fuse->session)) {
        LOG_err (FUSE_LOG, "No FUSE session !");
        return;
    }
/*
    if (event_add (hfs_fuse->ev_timer, &tv)) {
        LOG_err (FUSE_LOG, "event_add");
        return NULL;
    }
*/
}

// turn ASYNC read off
static void hfs_fuse_init (G_GNUC_UNUSED void *userdata, struct fuse_conn_info *conn)
{
    conn->async_read = 0;
}

// low level fuse reading operations
static void hfs_fuse_on_read (evutil_socket_t fd, short what, void *arg)
{
    HfsFuse *hfs_fuse = (HfsFuse *)arg;
    struct fuse_chan *ch = hfs_fuse->chan;
    int res;

    if (!ch) {
        LOG_err (FUSE_LOG, "No FUSE channel !");
        return;
    }

    if (fuse_session_exited (hfs_fuse->session)) {
        LOG_err (FUSE_LOG, "No FUSE session !");
        return;
    }
    
    // loop until we complete a recv
    do {
        // a new fuse_req is available
        res = fuse_chan_recv (&ch, hfs_fuse->recv_buf, hfs_fuse->recv_size);
    } while (res == -EINTR);

    if (res == 0)
        LOG_err (FUSE_LOG, "fuse_chan_recv gave EOF");

    if (res < 0 && res != -EAGAIN)
        LOG_err (FUSE_LOG, "fuse_chan_recv failed: %s", strerror(-res));
    
    if (res > 0) {
        // LOG_debug (FUSE_LOG, "got %d bytes from /dev/fuse", res);

        fuse_session_process (hfs_fuse->session, hfs_fuse->recv_buf, res, ch);
    }
    
    // reschedule
    if (event_add (hfs_fuse->ev, NULL))
        LOG_err (FUSE_LOG, "event_add");

    // ok, wait for the next event
    return;
}
/*}}}*/

/*{{{ readdir operation */

#define min(x, y) ((x) < (y) ? (x) : (y))

// return newly allocated buffer which holds directory entry
void hfs_fuse_add_dirbuf (fuse_req_t req, struct dirbuf *b, const char *name, fuse_ino_t ino, off_t file_size)
{
    struct stat stbuf;
    size_t oldsize = b->size;
    
    LOG_debug (FUSE_LOG, "add_dirbuf  ino: %d, name: %s", ino, name);

    // get required buff size
	b->size += fuse_add_direntry (req, NULL, 0, name, NULL, 0);

    // extend buffer
	b->p = (char *) g_realloc (b->p, b->size);
	memset (&stbuf, 0, sizeof (stbuf));
	stbuf.st_ino = ino;
    stbuf.st_size = file_size;
    // add entry
	fuse_add_direntry (req, b->p + oldsize, b->size - oldsize, name, &stbuf, b->size);
}

// readdir callback
// Valid replies: fuse_reply_buf() fuse_reply_err()
static void hfs_fuse_readdir_cb (fuse_req_t req, gboolean success, size_t max_size, off_t off, const char *buf, size_t buf_size)
{
    LOG_debug (FUSE_LOG, "readdir_cb  success: %s, buf_size: %zd, size: %zd, off: %"OFF_FMT, success?"YES":"NO", buf_size, max_size, off);

    if (!success) {
		fuse_reply_err (req, ENOTDIR);
        return;
    }

	if (off < buf_size)
		fuse_reply_buf (req, buf + off, min (buf_size - off, max_size));
	else
	    fuse_reply_buf (req, NULL, 0);
}

// FUSE lowlevel operation: readdir
// Valid replies: fuse_reply_buf() fuse_reply_err()
static void hfs_fuse_readdir (fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
    HfsFuse *hfs_fuse = fuse_req_userdata (req);

    LOG_debug (FUSE_LOG, "readdir  inode: %"INO_FMT", size: %zd, off: %"OFF_FMT, ino, size, off);
    
    // fill directory buffer for "ino" directory
    dir_tree_fill_dir_buf (hfs_fuse->dir_tree, ino, size, off, hfs_fuse_readdir_cb, req);
}
/*}}}*/

/*{{{ getattr operation */

// getattr callback
static void hfs_fuse_getattr_cb (fuse_req_t req, gboolean success, fuse_ino_t ino, int mode, off_t file_size, time_t ctime)
{
    struct stat stbuf;

    LOG_debug (FUSE_LOG, "getattr_cb  success: %s", success?"YES":"NO");
    if (!success) {
		fuse_reply_err (req, ENOENT);
        return;
    }
    memset (&stbuf, 0, sizeof(stbuf));
    stbuf.st_ino = ino;
    stbuf.st_mode = mode;
	stbuf.st_nlink = 1;
	stbuf.st_size = file_size;
    stbuf.st_ctime = ctime;
    stbuf.st_atime = ctime;
    stbuf.st_mtime = ctime;
    
    fuse_reply_attr (req, &stbuf, 1.0);
}

// FUSE lowlevel operation: getattr
// Valid replies: fuse_reply_attr() fuse_reply_err()
static void hfs_fuse_getattr (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    HfsFuse *hfs_fuse = fuse_req_userdata (req);
    
    LOG_debug (FUSE_LOG, "getattr  for %d", ino);

    dir_tree_getattr (hfs_fuse->dir_tree, ino, hfs_fuse_getattr_cb, req);
}
/*}}}*/

/*{{{ setattr operation */
// setattr callback
static void hfs_fuse_setattr_cb (fuse_req_t req, gboolean success, fuse_ino_t ino, int mode, off_t file_size)
{
    struct stat stbuf;

    LOG_debug (FUSE_LOG, "setattr_cb  success: %s", success?"YES":"NO");
    if (!success) {
		fuse_reply_err (req, ENOENT);
        return;
    }
    memset (&stbuf, 0, sizeof(stbuf));
    stbuf.st_ino = ino;
    stbuf.st_mode = mode;
	stbuf.st_nlink = 1;
	stbuf.st_size = file_size;
    
    fuse_reply_attr (req, &stbuf, 1.0);
}

// FUSE lowlevel operation: setattr
// Valid replies: fuse_reply_attr() fuse_reply_err()
static void hfs_fuse_setattr (fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi)
{
    HfsFuse *hfs_fuse = fuse_req_userdata (req);

    dir_tree_setattr (hfs_fuse->dir_tree, ino, attr, to_set, hfs_fuse_setattr_cb, req, fi);
}
/*}}}*/

/*{{{ lookup operation*/

// lookup callback
static void hfs_fuse_lookup_cb (fuse_req_t req, gboolean success, fuse_ino_t ino, int mode, off_t file_size, time_t ctime)
{
	struct fuse_entry_param e;

    LOG_debug (FUSE_LOG, "lookup_cb  success: %s", success?"YES":"NO");
    if (!success) {
		fuse_reply_err (req, ENOENT);
        return;
    }

    memset(&e, 0, sizeof(e));
    e.ino = ino;
    e.attr_timeout = 1.0;
    e.entry_timeout = 1.0;

    e.attr.st_ino = ino;
    e.attr.st_mode = mode;
	e.attr.st_nlink = 1;
	e.attr.st_size = file_size;
    e.attr.st_ctime = ctime;
    e.attr.st_atime = ctime;
    e.attr.st_mtime = ctime;

    fuse_reply_entry (req, &e);
}

// FUSE lowlevel operation: lookup
// Valid replies: fuse_reply_entry() fuse_reply_err()
static void hfs_fuse_lookup (fuse_req_t req, fuse_ino_t parent_ino, const char *name)
{
    HfsFuse *hfs_fuse = fuse_req_userdata (req);

    LOG_debug (FUSE_LOG, "lookup  name: %s parent inode: %"INO_FMT, name, parent_ino);

    dir_tree_lookup (hfs_fuse->dir_tree, parent_ino, name, hfs_fuse_lookup_cb, req);
}
/*}}}*/

/*{{{ open operation */

static void hfs_fuse_open_cb (fuse_req_t req, gboolean success, struct fuse_file_info *fi)
{
    if (success)
        fuse_reply_open (req, fi);
    else
        fuse_reply_err (req, ENOENT);
}

// FUSE lowlevel operation: open
// Valid replies: fuse_reply_open() fuse_reply_err()
static void hfs_fuse_open (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    HfsFuse *hfs_fuse = fuse_req_userdata (req);
    
    LOG_debug (FUSE_LOG, "[%p] open  inode: %d, flags: %d", fi, ino, fi->flags);

    dir_tree_file_open (hfs_fuse->dir_tree, ino, fi, hfs_fuse_open_cb, req);
}
/*}}}*/

/*{{{ create operation */
// create callback
void hfs_fuse_create_cb (fuse_req_t req, gboolean success, fuse_ino_t ino, int mode, off_t file_size, struct fuse_file_info *fi)
{
	struct fuse_entry_param e;

    LOG_debug (FUSE_LOG, "add_file_cb  success: %s", success?"YES":"NO");
    if (!success) {
		fuse_reply_err (req, ENOENT);
        return;
    }

    memset(&e, 0, sizeof(e));
    e.ino = ino;
    e.attr_timeout = 1.0;
    e.entry_timeout = 1.0;

    e.attr.st_ino = ino;
    e.attr.st_mode = mode;
	e.attr.st_nlink = 1;
	e.attr.st_size = file_size;

    fuse_reply_create (req, &e, fi);
}

// FUSE lowlevel operation: create
// Valid replies: fuse_reply_create() fuse_reply_err()
static void hfs_fuse_create (fuse_req_t req, fuse_ino_t parent_ino, const char *name, mode_t mode, struct fuse_file_info *fi)
{
    HfsFuse *hfs_fuse = fuse_req_userdata (req);
    
    LOG_debug (FUSE_LOG, "create  parent inode: %"INO_FMT", name: %s, mode: %d ", parent_ino, name, mode);

    dir_tree_file_create (hfs_fuse->dir_tree, parent_ino, name, mode, hfs_fuse_create_cb, req, fi);
}
/*}}}*/

/*{{{ release operation */

// FUSE lowlevel operation: release
// Valid replies: fuse_reply_err()
static void hfs_fuse_release (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    HfsFuse *hfs_fuse = fuse_req_userdata (req);

    LOG_debug (FUSE_LOG, "release  inode: %d, flags: %d", ino, fi->flags);

    dir_tree_file_release (hfs_fuse->dir_tree, ino, fi);

    fuse_reply_err (req, 0);
}
/*}}}*/

/*{{{ read operation */

// read callback
static void hfs_fuse_read_cb (fuse_req_t req, gboolean success, const char *buf, size_t buf_size)
{

    LOG_debug (FUSE_LOG, "[%p] <<<<< read_cb  success: %s IN buf: %zu", req, success?"YES":"NO", buf_size);

    if (!success) {
		fuse_reply_err (req, ENOENT);
        return;
    }

	fuse_reply_buf (req, buf, buf_size);
}

// FUSE lowlevel operation: read
// Valid replies: fuse_reply_buf() fuse_reply_err()
static void hfs_fuse_read (fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
    HfsFuse *hfs_fuse = fuse_req_userdata (req);
    
    LOG_debug (FUSE_LOG, "[%p] >>>> read  inode: %"INO_FMT", size: %zd, off: %"OFF_FMT, req, ino, size, off);

    dir_tree_file_read (hfs_fuse->dir_tree, ino, size, off, hfs_fuse_read_cb, req, fi);
}
/*}}}*/

/*{{{ write operation */
// write callback
static void hfs_fuse_write_cb (fuse_req_t req, gboolean success, size_t count)
{
    // LOG_debug (FUSE_LOG, "write_cb  success: %s", success?"YES":"NO");

    if (!success) {
		fuse_reply_err (req, ENOENT);
        return;
    }
    
    fuse_reply_write (req, count);
}
// FUSE lowlevel operation: write
// Valid replies: fuse_reply_write() fuse_reply_err()
static void hfs_fuse_write (fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off, struct fuse_file_info *fi)
{
    HfsFuse *hfs_fuse = fuse_req_userdata (req);
    
    // LOG_debug (FUSE_LOG, "write  inode: %"INO_FMT", size: %zd, off: %"OFF_FMT, ino, size, off);

    dir_tree_file_write (hfs_fuse->dir_tree, ino, buf, size, off, hfs_fuse_write_cb, req, fi);
}
/*}}}*/

/*{{{ forget operation*/

// forget callback
static void hfs_fuse_forget_cb (fuse_req_t req, gboolean success)
{
    if (success)
        fuse_reply_none (req);
    else
        fuse_reply_none (req);
}

// Forget about an inode
// Valid replies: fuse_reply_none
// XXX: it removes files and directories
static void hfs_fuse_forget (fuse_req_t req, fuse_ino_t ino, unsigned long nlookup)
{
    HfsFuse *hfs_fuse = fuse_req_userdata (req);
    
    LOG_debug (FUSE_LOG, "forget  inode: %"INO_FMT", nlookup: %lu", ino, nlookup);
    
    if (nlookup != 0) {
        LOG_debug (FUSE_LOG, "Ignoring forget with nlookup > 0");
        fuse_reply_none (req);
    } else
        dir_tree_file_remove (hfs_fuse->dir_tree, ino, hfs_fuse_forget_cb, req);
}
/*}}}*/

/*{{{ unlink operation*/

static void hfs_fuse_unlink_cb (fuse_req_t req, gboolean success)
{
    LOG_debug (FUSE_LOG, "[%p] success: %s", req, success ? "TRUE" : "FALSE");

    if (success)
        fuse_reply_err (req, 0);
    else
        fuse_reply_err (req, ENOENT);
}

// Remove a file
// Valid replies: fuse_reply_err
// XXX: not used, see hfs_fuse_forget
static void hfs_fuse_unlink (fuse_req_t req, fuse_ino_t parent, const char *name)
{
    HfsFuse *hfs_fuse = fuse_req_userdata (req);
    
    LOG_debug (FUSE_LOG, "[%p] unlink  parent_ino: %"INO_FMT", name: %s", req, parent, name);

    dir_tree_file_unlink (hfs_fuse->dir_tree, parent, name, hfs_fuse_unlink_cb, req);
}
/*}}}*/

/*{{{ mkdir operator */

// mkdir callback
static void hfs_fuse_mkdir_cb (fuse_req_t req, gboolean success, fuse_ino_t ino, int mode, off_t file_size, time_t ctime)
{
	struct fuse_entry_param e;

    LOG_debug (FUSE_LOG, "mkdir_cb  success: %s, ino: %"INO_FMT, success?"YES":"NO", ino);
    if (!success) {
		fuse_reply_err (req, ENOENT);
        return;
    }

    memset(&e, 0, sizeof(e));
	e.ino = ino;
	e.attr_timeout = 1.0;
	e.entry_timeout = 1.0;
    //e.attr.st_mode = S_IFDIR | 0755;
    e.attr.st_mode = mode;
	e.attr.st_nlink = 2;
    e.attr.st_ctime = ctime;
    e.attr.st_atime = ctime;
    e.attr.st_mtime = ctime;
    
    e.attr.st_ino = ino;
	e.attr.st_size = file_size;
    
    fuse_reply_entry (req, &e);
}

// Create a directory
// Valid replies: fuse_reply_entry fuse_reply_err
static void hfs_fuse_mkdir (fuse_req_t req, fuse_ino_t parent_ino, const char *name, mode_t mode)
{
    HfsFuse *hfs_fuse = fuse_req_userdata (req);
    
    LOG_debug (FUSE_LOG, "mkdir  parent_ino: %"INO_FMT", name: %s, mode: %d", parent_ino, name, mode);

    dir_tree_dir_create (hfs_fuse->dir_tree, parent_ino, name, mode, hfs_fuse_mkdir_cb, req);
}
/*}}}*/

/*{{{ rmdir operator */

// Remove a directory
// Valid replies: fuse_reply_err
// XXX: not used, see hfs_fuse_forget
static void hfs_fuse_rmdir (fuse_req_t req, fuse_ino_t parent_ino, const char *name)
{
    HfsFuse *hfs_fuse = fuse_req_userdata (req);
    
    LOG_debug (FUSE_LOG, "rmdir  parent_ino: %"INO_FMT", name: %s", parent_ino, name);

    fuse_reply_err (req, 0);
}
/*}}}*/
