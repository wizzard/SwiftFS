AM_CPPFLAGS = -I$(top_srcdir)/include
bin_PROGRAMS = http_client_test http_client_test_2 client_pool_test
bin_PROGRAMS += auth_client_test conf_test hfs_encryption_test hfs_range_test
bin_PROGRAMS += hfs_stats_srv_test
EXTRA_DIST = test.conf.xml

http_client_test_SOURCES = $(top_srcdir)/src/http_client.c
http_client_test_SOURCES += $(top_srcdir)/src/auth_client.c 
http_client_test_SOURCES += $(top_srcdir)/src/log.c
http_client_test_SOURCES += $(top_srcdir)/src/utils.c
http_client_test_SOURCES += $(top_srcdir)/src/conf.c
http_client_test_SOURCES += http_client_test.c
http_client_test_CFLAGS = $(AM_CFLAGS) $(DEPS_CFLAGS)
http_client_test_LDADD = $(AM_LDADD) $(DEPS_LIBS)

http_client_test_2_SOURCES = $(top_srcdir)/src/http_client.c
http_client_test_2_SOURCES += $(top_srcdir)/src/auth_client.c 
http_client_test_2_SOURCES += $(top_srcdir)/src/log.c
http_client_test_2_SOURCES += $(top_srcdir)/src/utils.c
http_client_test_2_SOURCES += $(top_srcdir)/src/conf.c
http_client_test_2_SOURCES += http_client_test_2.c
http_client_test_2_CFLAGS = $(AM_CFLAGS) $(DEPS_CFLAGS)
http_client_test_2_LDADD = $(AM_LDADD) $(DEPS_LIBS)


client_pool_test_SOURCES = $(top_srcdir)/src/http_client.c
client_pool_test_SOURCES += $(top_srcdir)/src/client_pool.c 
client_pool_test_SOURCES += $(top_srcdir)/src/auth_client.c 
client_pool_test_SOURCES += $(top_srcdir)/src/log.c
client_pool_test_SOURCES += $(top_srcdir)/src/utils.c
client_pool_test_SOURCES += $(top_srcdir)/src/conf.c
client_pool_test_SOURCES += $(top_srcdir)/src/hfs_stats_srv.c
client_pool_test_SOURCES += $(top_srcdir)/src/http_connection.c
client_pool_test_SOURCES += client_pool_test.c
client_pool_test_CFLAGS = $(AM_CFLAGS) $(DEPS_CFLAGS)
client_pool_test_LDADD = $(AM_LDADD) $(DEPS_LIBS)

auth_client_test_SOURCES = $(top_srcdir)/src/auth_client.c
auth_client_test_SOURCES += $(top_srcdir)/src/log.c
auth_client_test_SOURCES += $(top_srcdir)/src/utils.c
auth_client_test_SOURCES += $(top_srcdir)/src/conf.c
auth_client_test_SOURCES += auth_client_test.c
auth_client_test_CFLAGS = $(AM_CFLAGS) $(DEPS_CFLAGS)
auth_client_test_LDADD = $(AM_LDADD) $(DEPS_LIBS)

conf_test_SOURCES = $(top_srcdir)/src/log.c
conf_test_SOURCES += $(top_srcdir)/src/utils.c
conf_test_SOURCES += $(top_srcdir)/src/conf.c
conf_test_SOURCES += conf_test.c
conf_test_CFLAGS = $(AM_CFLAGS) $(DEPS_CFLAGS)
conf_test_LDADD = $(AM_LDADD) $(DEPS_LIBS)

hfs_encryption_test_SOURCES = $(top_srcdir)/src/log.c
hfs_encryption_test_SOURCES += $(top_srcdir)/src/utils.c
hfs_encryption_test_SOURCES += $(top_srcdir)/src/conf.c
hfs_encryption_test_SOURCES += $(top_srcdir)/src/hfs_encryption.c
hfs_encryption_test_SOURCES += hfs_encryption_test.c
hfs_encryption_test_CFLAGS = $(AM_CFLAGS) $(DEPS_CFLAGS)
hfs_encryption_test_LDADD = $(AM_LDADD) $(DEPS_LIBS)

hfs_range_test_SOURCES = $(top_srcdir)/src/hfs_range.c
hfs_range_test_SOURCES += hfs_range_test.c
hfs_range_test_CFLAGS = $(AM_CFLAGS) $(DEPS_CFLAGS)
hfs_range_test_LDADD = $(AM_LDADD) $(DEPS_LIBS)

hfs_stats_srv_test_SOURCES = $(top_srcdir)/src/hfs_stats_srv.c
hfs_stats_srv_test_SOURCES += $(top_srcdir)/src/conf.c
hfs_stats_srv_test_SOURCES += $(top_srcdir)/src/utils.c
hfs_stats_srv_test_SOURCES += $(top_srcdir)/src/log.c
hfs_stats_srv_test_SOURCES += hfs_stats_srv_test.c
hfs_stats_srv_test_CFLAGS = $(AM_CFLAGS) $(DEPS_CFLAGS)
hfs_stats_srv_test_LDADD = $(AM_LDADD) $(DEPS_LIBS)

