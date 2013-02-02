AM_CPPFLAGS = -I$(top_srcdir)/include
bin_PROGRAMS = http_client_test client_pool_test auth_client_test conf_test
EXTRA_DIST = test.conf.xml

http_client_test_SOURCES = $(top_srcdir)/src/http_client.c
http_client_test_SOURCES += $(top_srcdir)/src/log.c
http_client_test_SOURCES += $(top_srcdir)/src/utils.c
http_client_test_SOURCES += http_client_test.c
http_client_test_CFLAGS = $(AM_CFLAGS) $(DEPS_CFLAGS)
http_client_test_LDADD = $(AM_LDADD) $(DEPS_LIBS)

client_pool_test_SOURCES = $(top_srcdir)/src/http_client.c
client_pool_test_SOURCES += $(top_srcdir)/src/client_pool.c 
client_pool_test_SOURCES += $(top_srcdir)/src/log.c
client_pool_test_SOURCES += $(top_srcdir)/src/utils.c
client_pool_test_SOURCES += $(top_srcdir)/src/http_connection.c
client_pool_test_SOURCES += client_pool_test.c
client_pool_test_CFLAGS = $(AM_CFLAGS) $(DEPS_CFLAGS)
client_pool_test_LDADD = $(AM_LDADD) $(DEPS_LIBS)

auth_client_test_SOURCES = $(top_srcdir)/src/auth_client.c
auth_client_test_SOURCES += $(top_srcdir)/src/log.c
auth_client_test_SOURCES += $(top_srcdir)/src/utils.c
auth_client_test_SOURCES += auth_client_test.c
auth_client_test_CFLAGS = $(AM_CFLAGS) $(DEPS_CFLAGS)
auth_client_test_LDADD = $(AM_LDADD) $(DEPS_LIBS)

conf_test_SOURCES = $(top_srcdir)/src/conf.c
conf_test_SOURCES += $(top_srcdir)/src/log.c
conf_test_SOURCES += $(top_srcdir)/src/utils.c
conf_test_SOURCES += conf_test.c
conf_test_CFLAGS = $(AM_CFLAGS) $(DEPS_CFLAGS)
conf_test_LDADD = $(AM_LDADD) $(DEPS_LIBS)
