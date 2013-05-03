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
#include "hfs_range.h"

struct _HfsRange {
    GList *l_intervals; // sorted list of intervals
};

typedef struct {
    guint64 start;
    guint64 end;
} Interval;

HfsRange *hfs_range_create ()
{
    HfsRange *range;

    range = g_new0 (HfsRange, 1);
    range->l_intervals = NULL;

    return range;
}

void hfs_range_destroy (HfsRange *range)
{
    GList *l;

    for (l = g_list_first (range->l_intervals); l; l = g_list_next (l)) {
        Interval *in = (Interval *) l->data;
        g_free (in);
    }
    g_list_free (range->l_intervals);
    g_free (range);
}

static gint intervals_compare (Interval *a, Interval *b)
{
    if (a->start < b->start)
        return -1;
    else if (a->start > b->start)
        return 1;
    else 
        return 0;
}

void hfs_range_add (HfsRange *range, guint64 start, guint64 end)
{
    GList *l;
    gboolean found = FALSE;

    l = g_list_first (range->l_intervals);
    while (l) {
        Interval *in = (Interval *) l->data;
        
        // is in range
        if (in->start <= start && in->end >= end) {
            return;
        }

        // overlaps
        if ((in->start >= start && in->start <= end) || (in->end >= start && in->end <= end)) {
            GList *j;
            found = TRUE;
            // extend it
            if (in->end < end)
                in->end = end;
            if (in->start > start)
                in->start = start;

            
            j = l->next;
            while (j) {
                // extend
                Interval *in1 = (Interval *) j->data;
                if ((in->start >= in1->start && in->start <= in1->end) || 
                    (in->end >= in1->start && in->end <= in1->end) || 
                    (in->start <= in1->start && in->end >= in1->end)) {
                    GList *l_save;

                    if (in->end < in1->end)
                        in->end = in1->end;
                    if (in->start > in1->start)
                        in->start = in1->start;

                    l_save = j->next;
                    range->l_intervals = g_list_delete_link (range->l_intervals, j);
                    j = l_save;

                    g_free (in1);
                } else 
                    j = j->next;
            }
        }

        l = l->next;
    }

    // not found
    if (!found) {
        Interval *in = g_new0 (Interval, 1);
        in->start = start;
        in->end = end;
        range->l_intervals = g_list_insert_sorted (range->l_intervals, in, (GCompareFunc) intervals_compare);
    }
}

gboolean hfs_range_contain (HfsRange *range, guint64 start, guint64 end)
{
    GList *l;

    for (l = g_list_first (range->l_intervals); l; l = g_list_next (l)) {
        Interval *in = (Interval *) l->data;

        if (in->start <= start && in->end >= end)
            return TRUE;
    }

    return FALSE;
}

gint hfs_range_count (HfsRange *range)
{
    return g_list_length (range->l_intervals);
}

void hfs_range_print (HfsRange *range)
{
    GList *l;

    g_printf ("===\n");
    for (l = g_list_first (range->l_intervals); l; l = g_list_next (l)) {
        Interval *in = (Interval *) l->data;
        g_printf ("[%lu %lu]\n", in->start, in->end);
    }
}

