#define LIBSSH_STATIC 1

#include <stdio.h>
#include <stdlib.h>
#include "src/thpool.h"
#include "src/list.h"
#include "src/utils.h"

void usage(char *program) {
    printf("Usage ./%s <max number threads> <is debug 1/0 - default:0> <\n", program);
}

/**
 * The main
 * @param argc
 * @param argv
 * @return
 */
int main(int argc, char *argv[]) {

    t_config *config = t_config_create();

    // Parse args
    if (argc > 1) {
        config->debug = 0;
        config->threads = atoi(argv[1]);
        if (config->threads == 0) {
            config->threads = 2;
        }
        if (argc > 2) {
            config->debug = atoi(argv[2]);
        }
    } else {
        usage(argv[0]);
        return -1;
    }
    list_t *ips = get_ip_addresses();

    // Create threads
    unsigned int total_targets = ips->len;
    if (total_targets > 0) {
        threadpool thpool = thpool_init(min(config->threads, total_targets));
        t_thread_data data[total_targets];
        for (int i = 0; i < total_targets; i++) {
            list_node_t *ip_node = list_at(ips, i);
            t_ip_address *ip_address = (t_ip_address *) ip_node->val;
            data[i].ip_address = ip_address;
            data[i].config = config;
            thpool_add_work(thpool, (void *) process_chunk, (void *) &data[i]);
        }
        list_destroy(ips);
        thpool_wait(thpool);
        thpool_destroy(thpool);

    } else {
        list_destroy(ips);
        printf("Blah! No targets found.\n");
        return -1;
    }
    return 1;

}