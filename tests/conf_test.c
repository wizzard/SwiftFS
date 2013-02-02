/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#include "global.h"
#include "conf.h"

void test_conf_setup (ConfData **conf, gconstpointer test_data)
{
    *conf = conf_create ();
}

void test_conf_destroy (ConfData **conf, gconstpointer test_data)
{
    conf_destroy (*conf);
}

void test_conf_parse_file (ConfData **conf, gconstpointer test_data)
{
    gboolean res;
    
    res = conf_parse_file (*conf, "test.conf.xml");
	g_assert (res == TRUE);
}

void test_conf_get_string (ConfData **conf, gconstpointer test_data)
{
    gboolean res;
    const gchar *str;
    
    res = conf_parse_file (*conf, "test.conf.xml");
	g_assert (res == TRUE);

    str = conf_get_string (*conf, "tmp.a.tmp");
    g_assert_cmpstr (str, ==, "TEST_OK");
}

void test_conf_get_int (ConfData **conf, gconstpointer test_data)
{
    gboolean res;
    gint32 i;
    
    res = conf_parse_file (*conf, "test.conf.xml");
	g_assert (res == TRUE);

    i = conf_get_int (*conf, "tmp.int");
    g_assert_cmpint (i, ==, 445);
}

void test_conf_get_boolean (ConfData **conf, gconstpointer test_data)
{
    gboolean res;
    gboolean b;
    
    res = conf_parse_file (*conf, "test.conf.xml");
	g_assert (res == TRUE);

    b = conf_get_boolean (*conf, "tmp.a.b.b");
    g_assert (b == TRUE);
}

void test_conf_get_list (ConfData **conf, gconstpointer test_data)
{
    gboolean res;
    GList *l, *l_tmp;
    int itr = 0;
    gchar *str;
    
    res = conf_parse_file (*conf, "test.conf.xml");
	g_assert (res == TRUE);

    l = conf_get_list (*conf, "tmp.list");
    g_assert (l != NULL);

    for (l_tmp = g_list_first (l); l_tmp; l_tmp = l_tmp->next) {
        str = (gchar *) l_tmp->data;
        if (itr == 0) {
            g_assert_cmpstr (str, ==, "TEST_1");
        } else if (itr == 1) {
            g_assert_cmpstr (str, ==, "TEST_2");
        } else if (itr == 2) {
            g_assert_cmpstr (str, ==, "TEST_3");
        } else if (itr == 3) {
            g_assert_cmpstr (str, ==, "TEST_4");

        } else {
            g_assert_not_reached ();
        }
        itr++;
    }

}

int main (int argc, char *argv[])
{
    g_test_init (&argc, &argv, NULL);

	g_test_add ("/utils/conf_parse_file", ConfData*, 0, test_conf_setup, test_conf_parse_file, test_conf_destroy);
	g_test_add ("/utils/conf_get_string", ConfData*, 0, test_conf_setup, test_conf_get_string, test_conf_destroy);
	g_test_add ("/utils/conf_get_int", ConfData*, 0, test_conf_setup, test_conf_get_int, test_conf_destroy);
	g_test_add ("/utils/conf_get_boolean", ConfData*, 0, test_conf_setup, test_conf_get_boolean, test_conf_destroy);
	g_test_add ("/utils/conf_get_list", ConfData*, 0, test_conf_setup, test_conf_get_list, test_conf_destroy);

    return g_test_run ();
}
