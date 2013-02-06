/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#include "hfs_range.h"

static void hfs_range_test_setup (HfsRange **range, gconstpointer test_data)
{
    *range = hfs_range_create ();
}

static void hfs_range_test_destroy (HfsRange **range, gconstpointer test_data)
{
    hfs_range_destroy (*range);
}

static void hfs_range_test_add (HfsRange **range, gconstpointer test_data)
{
    hfs_range_add (*range, 1, 10);
    g_assert (hfs_range_contain (*range, 2, 5) == TRUE);
    g_assert (hfs_range_count (*range) == 1);
}

static void hfs_range_test_extend_1 (HfsRange **range, gconstpointer test_data)
{
    hfs_range_add (*range, 1, 10);
    hfs_range_add (*range, 2, 12);
    g_assert (hfs_range_contain (*range, 2, 12) == TRUE);
    g_assert (hfs_range_count (*range) == 1);
}

static void hfs_range_test_extend_2 (HfsRange **range, gconstpointer test_data)
{
    hfs_range_add (*range, 1, 10);
    hfs_range_add (*range, 2, 12);
    hfs_range_add (*range, 10, 20);
    hfs_range_add (*range, 1, 50);
    hfs_range_add (*range, 60, 70);
    hfs_range_add (*range, 4, 5);
    hfs_range_add (*range, 7, 52);
    g_assert (hfs_range_contain (*range, 2, 12) == TRUE);
    g_assert (hfs_range_count (*range) == 2);
    hfs_range_print (*range);
}


static void hfs_range_test_remove_1 (HfsRange **range, gconstpointer test_data)
{
    hfs_range_add (*range, 1, 10);
    hfs_range_add (*range, 11, 15);
    hfs_range_add (*range, 2, 14);
    g_assert (hfs_range_contain (*range, 2, 14) == TRUE);
    g_assert (hfs_range_count (*range) == 1);
    hfs_range_print (*range);
}

static void hfs_range_test_remove_2 (HfsRange **range, gconstpointer test_data)
{
    hfs_range_add (*range, 1, 9);
    hfs_range_add (*range, 11, 15);
    hfs_range_add (*range, 16, 20);
    hfs_range_add (*range, 25, 30);
    hfs_range_add (*range, 25, 30); 
    hfs_range_add (*range, 32, 36); 
    hfs_range_add (*range, 40, 50); 
    hfs_range_print (*range);


    hfs_range_add (*range, 10, 32); 
    g_assert (hfs_range_contain (*range, 2, 14) == FALSE);
    g_assert (hfs_range_contain (*range, 1, 9) == TRUE);
    g_assert (hfs_range_contain (*range, 10, 35) == TRUE);
    g_assert (hfs_range_count (*range) == 3);
    hfs_range_print (*range);
}

static void hfs_range_test_remove_3 (HfsRange **range, gconstpointer test_data)
{
    hfs_range_add (*range, 1, 9);
    hfs_range_add (*range, 40, 50);

    hfs_range_add (*range, 20, 25);
    hfs_range_add (*range, 15, 23);

    hfs_range_add (*range, 24, 30);

    hfs_range_add (*range, 10, 35); 

    g_assert (hfs_range_contain (*range, 2, 14) == FALSE);
    g_assert (hfs_range_contain (*range, 1, 9) == TRUE);
    g_assert (hfs_range_contain (*range, 10, 35) == TRUE);
    g_assert (hfs_range_count (*range) == 3);
    hfs_range_print (*range);
}


int main (int argc, char *argv[])
{
    g_test_init (&argc, &argv, NULL);

	g_test_add ("/range/range_test_add", HfsRange *, 0, hfs_range_test_setup, hfs_range_test_add, hfs_range_test_destroy);
	g_test_add ("/range/range_test_add", HfsRange *, 0, hfs_range_test_setup, hfs_range_test_extend_1, hfs_range_test_destroy);
	g_test_add ("/range/range_test_add", HfsRange *, 0, hfs_range_test_setup, hfs_range_test_extend_2, hfs_range_test_destroy);
	g_test_add ("/range/range_test_add", HfsRange *, 0, hfs_range_test_setup, hfs_range_test_remove_1, hfs_range_test_destroy);
	g_test_add ("/range/range_test_add", HfsRange *, 0, hfs_range_test_setup, hfs_range_test_remove_2, hfs_range_test_destroy);
	g_test_add ("/range/range_test_add", HfsRange *, 0, hfs_range_test_setup, hfs_range_test_remove_3, hfs_range_test_destroy);

    return g_test_run ();
}
