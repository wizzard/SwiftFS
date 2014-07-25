AM_CPPFLAGS = -I$(top_srcdir)/include -DSYSCONFDIR=\""$(sysconfdir)/@PACKAGE@/"\"
bin_PROGRAMS = swiftfs
swiftfs_SOURCES = log.c
swiftfs_SOURCES += conf.c
swiftfs_SOURCES += dir_tree.c
swiftfs_SOURCES += hfs_fuse.c
swiftfs_SOURCES += http_connection.c
swiftfs_SOURCES += http_connection_dir_list.c
swiftfs_SOURCES += http_connection_file_send.c
swiftfs_SOURCES += http_connection_container.c
swiftfs_SOURCES += auth_client.c
swiftfs_SOURCES += http_client.c
swiftfs_SOURCES += client_pool.c
swiftfs_SOURCES += hfs_file_operation.c
swiftfs_SOURCES += cache_mng.c
swiftfs_SOURCES += hfs_encryption.c
swiftfs_SOURCES += utils.c
swiftfs_SOURCES += hfs_range.c
swiftfs_SOURCES += hfs_stats_srv.c
swiftfs_SOURCES += main.c

swiftfs_CFLAGS = $(AM_CFLAGS) $(DEPS_CFLAGS)
swiftfs_LDADD = $(AM_LDADD) $(DEPS_LIBS) -lssl
