#define LIBSSH_STATIC 1

#include <stdio.h>
#include <stdlib.h>
#include "src/thpool.h"
#include "src/list.h"
#include "src/utils.h"

/**
 * The main
 * @param argc
 * @param argv
 * @return
 */
int main(int argc, char *argv[]) {

    int max_total_threads;
    // Get total threads
    if (argc == 2) {
        max_total_threads = atoi(argv[1]);
        if (max_total_threads == 0) {
            max_total_threads = 1;
        }
        printf("%d", max_total_threads);
    } else {
        printf("Usage %s <number of maximum threads>\n", argv[0]);
        return -1;
    }
    list_t *ips = get_ip_addresses();
    int total_targets = ips->len;
    if (total_targets > 0) {
        list_t *combinations;
        combinations = get_user_pass_combinations();
        threadpool thpool = thpool_init(max_total_threads);
        t_thread_data data[total_targets];
        for (int i = 0; i < total_targets; i++) {
            list_node_t *ip_node = list_at(ips, i);
            t_ip_address *ip_address = (t_ip_address *) ip_node->val;
            data[i].combinations = combinations;
            data[i].ip_address = ip_address;
            thpool_add_work(thpool, (void *) process_chunk, (void *) &data[i]);
        }
        list_destroy(combinations);
        thpool_wait(thpool);
        thpool_destroy(thpool);

    } else {
        printf("Blah! No targets found.\n");
        return -1;
    }

    list_destroy(ips);

    return 1;

}