AM_CPPFLAGS = -I$(top_srcdir)/include -DSYSCONFDIR=\""$(sysconfdir)/@PACKAGE@/"\" 
bin_PROGRAMS = hydrafs
hydrafs_SOURCES = log.c
hydrafs_SOURCES += conf.c
hydrafs_SOURCES += dir_tree.c  
hydrafs_SOURCES += hfs_fuse.c  
hydrafs_SOURCES += http_connection.c
hydrafs_SOURCES += http_connection_dir_list.c
hydrafs_SOURCES += http_connection_file_send.c
hydrafs_SOURCES += http_connection_container.c
hydrafs_SOURCES += auth_client.c
hydrafs_SOURCES += http_client.c
hydrafs_SOURCES += client_pool.c
hydrafs_SOURCES += hfs_file_operation.c
hydrafs_SOURCES += cache_mng.c
hydrafs_SOURCES += hfs_encryption.c
hydrafs_SOURCES += utils.c
hydrafs_SOURCES += hfs_range.c
hydrafs_SOURCES += main.c

hydrafs_CFLAGS = $(AM_CFLAGS) $(DEPS_CFLAGS)
hydrafs_LDADD = $(AM_LDADD) $(DEPS_LIBS)
