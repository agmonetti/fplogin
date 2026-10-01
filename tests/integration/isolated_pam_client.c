/* Built only in a private temporary directory by verify_isolated_pam.py.
 * PAM service names and configuration directory are provided by that script;
 * no system PAM configuration is opened or modified by this client.
 */
#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t term_seen;

static void on_term(int signal_number)
{
    (void)signal_number;
    term_seen = 1;
    /* async-signal-safe; matches a helper whose event loop cannot dispatch
     * its queued termination while pam_authenticate is blocking. */
    static const char notice[] = "SIGTERM_SEEN\n";
    (void)write(STDOUT_FILENO, notice, sizeof(notice) - 1);
}

static int conversation(int count, const struct pam_message **messages,
                        struct pam_response **responses, void *context)
{
    (void)context;
    if (count <= 0 || !messages || !responses)
        return PAM_CONV_ERR;
    struct pam_response *result = calloc((size_t)count, sizeof(*result));
    if (!result)
        return PAM_BUF_ERR;
    for (int i = 0; i < count; i++) {
        if (!messages[i]) {
            free(result);
            return PAM_CONV_ERR;
        }
        /* Never log the message text or return a credential. An informational
         * fingerprint prompt is enough to establish that fprintd responded. */
        if (messages[i]->msg_style == PAM_TEXT_INFO ||
            messages[i]->msg_style == PAM_ERROR_MSG) {
            printf("PROMPT style=%d\n", messages[i]->msg_style);
        } else {
            free(result);
            return PAM_CONV_ERR;
        }
    }
    *responses = result;
    return PAM_SUCCESS;
}

int main(int argc, char **argv)
{
    if (argc != 5 || (strcmp(argv[1], "denied") != 0 &&
                      strcmp(argv[1], "fingerprint") != 0)) {
        fprintf(stderr, "usage: isolated_pam_client denied|fingerprint confdir service user\n");
        return 2;
    }
    if (strcmp(argv[1], "fingerprint") == 0) {
        struct sigaction action = {0};
        action.sa_handler = on_term;
        action.sa_flags = SA_RESTART;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGTERM, &action, NULL) != 0)
            return 2;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    struct pam_conv conv = { .conv = conversation, .appdata_ptr = NULL };
    pam_handle_t *handle = NULL;
    int rc = pam_start_confdir(argv[3], argv[4], &conv, argv[2], &handle);
    printf("START rc=%d\n", rc);
    if (rc != PAM_SUCCESS)
        return 3;
    printf("READY\nAUTH_ENTER\n");
    rc = pam_authenticate(handle, 0);
    printf("AUTH_RETURN rc=%d term=%d\n", rc, term_seen != 0);
    if (strcmp(argv[1], "fingerprint") == 0) {
        /* No real login, credential establishment, or session startup here. */
        pam_end(handle, rc);
        return 0;
    }
    if (rc != PAM_SUCCESS) {
        pam_end(handle, rc);
        return 4;
    }
    printf("ACCOUNT_ENTER\n");
    rc = pam_acct_mgmt(handle, 0);
    printf("ACCOUNT_RETURN rc=%d\n", rc);
    if (rc == PAM_SUCCESS) {
        /* These branches model the real post-account PAM sequence and are
         * unreachable under this fixture's required pam_deny account rule.
         * Even if the fixture breaks, its session rule is also pam_deny. */
        printf("SETCRED_ENTER\n");
        rc = pam_setcred(handle, PAM_ESTABLISH_CRED);
        printf("SETCRED_RETURN rc=%d\n", rc);
        if (rc == PAM_SUCCESS) {
            printf("SESSION_ENTER\n");
            rc = pam_open_session(handle, 0);
            printf("SESSION_RETURN rc=%d\n", rc);
        }
        pam_end(handle, rc);
        return 5;
    }
    pam_end(handle, rc);
    return rc != PAM_SUCCESS ? 0 : 6;
}
