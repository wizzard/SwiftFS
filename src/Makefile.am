AM_CPPFLAGS = -I$(top_srcdir)/include -DSYSCONFDIR=\""$(sysconfdir)/@PACKAGE@/"\" 
bin_PROGRAMS = hfs
hfs_SOURCES = log.c
hfs_SOURCES += dir_tree.c  
hfs_SOURCES += hfs_fuse.c  
hfs_SOURCES += http_connection.c
hfs_SOURCES += http_connection_dir_list.c
hfs_SOURCES += http_connection_file_send.c
hfs_SOURCES += http_client.c
hfs_SOURCES += client_pool.c
hfs_SOURCES += file_entry.c
hfs_SOURCES += cache_mng.c
hfs_SOURCES += utils.c
hfs_SOURCES += main.c

hfs_CFLAGS = $(AM_CFLAGS) $(DEPS_CFLAGS)
hfs_LDADD = $(AM_LDADD) $(DEPS_LIBS)
