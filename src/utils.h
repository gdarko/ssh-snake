//
// Created by darko on 5/3/18.
//
#ifndef UTILS_H
#define UTILS_H
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <libssh/libssh.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "list.h"

/**
 * t_login_combination structure
 */
struct t_login_combination {
    char username[255];
    char password[255];
} typedef t_login_combination;

/**
 * t_ip_address structure
 */
struct t_ip_address {
    char ip[255];
} typedef t_ip_address;

/**
 * The thread structure
 */
struct t_thread_data {
    list_t *combinations;
    t_ip_address *ip_address;
} typedef t_thread_data;

/**
 * The t_login_combination constructor
 * @param user
 * @param pass
 * @return
 */
t_login_combination *t_combination_create(char *user, char *pass);

/**
 * The t_login_combination constructor
 * @param user
 * @param pass
 * @return
 */
t_ip_address *t_ipaddress_create(char *ipaddr);

/**
 * The thread data object create
 * @param ip_addresses
 * @param combinations
 * @return
 */
t_thread_data *t_thread_data_create();

/**
 * The t_login_combination destructor
 * @param combination
 * @return void
 */
void *t_combination_destroy(t_login_combination *self);

/**
 * The t_login_combination destructor
 * @param ipaddr
 * @return void
 */
void *t_ipaddress_destroy(t_ip_address *self);

/**
 * The thread data destructor
 * @param data
 * @return void
 */
void *t_thread_data_destroy(t_thread_data *self);

/**
 * Writes text to file
 * @param msg
 * @param filename
 * @param flag
 */
void write_to_file(char *msg, char *filename, char *flag);

/**
 * Write
 * @param username
 * @param password
 * @param host
 * @return
 */
void write_auth_details(char *username, char *password, char *host);

/**
 * Write log
 * @param msg
 */
void write_log(char *msg);

/**
 * Is valid ipv4
 * @param ipAddress
 * @return
 */
int is_valid_ipv4(char *ipAddress);

/**
 * Creates dir if not exist
 * @param dir
 * @return
 */
int maybe_create_dir(char *dir);

/**
 * The ip addresses found by pscan2
 * @return
 */
list_t *get_ip_addresses();

/**
 * Used to collect the combinations from the pass file
 * @return
 */
list_t *get_user_pass_combinations();

/**
 * Verify ssh auth
 * @param username
 * @param password
 * @param host
 * @return
 */
int ssh_auth(char *username, char *password, char *host);

/**
 * Attack target
 * @param ip_object
 * @param combination
 */
void attack_target(t_ip_address * ip_object, list_t * combinations);

/**
 * Chunk process from thread
 * @param t_data
 * @return
 */
void process_chunk(void *t_data);

#endif //UTILS_H




