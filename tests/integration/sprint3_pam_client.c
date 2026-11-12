/* Sprint 3 PAM stack probe. Runs only inside the disposable lab container.
 * Never supplies a credential: an echo-off (password) prompt is recorded and
 * refused, so any password request by the fingerprint service is detected. */
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int echo_off_requests;

static int conversation(int count, const struct pam_message **messages,
                        struct pam_response **responses, void *context)
{
    (void)context;
    for (int i = 0; i < count; i++) {
        if (messages[i]->msg_style == PAM_PROMPT_ECHO_OFF ||
            messages[i]->msg_style == PAM_PROMPT_ECHO_ON) {
            echo_off_requests++;
            return PAM_CONV_ERR;
        }
    }
    *responses = calloc((size_t)count, sizeof(**responses));
    return *responses ? PAM_SUCCESS : PAM_BUF_ERR;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: sprint3_pam_client auth|account|session|chauthtok service user\n");
        return 2;
    }
    struct pam_conv conv = { .conv = conversation, .appdata_ptr = NULL };
    pam_handle_t *handle = NULL;
    int rc = pam_start(argv[2], argv[3], &conv, &handle);
    if (rc != PAM_SUCCESS) {
        printf("START rc=%d\n", rc);
        return 3;
    }
    if (strcmp(argv[1], "auth") == 0)
        rc = pam_authenticate(handle, 0);
    else if (strcmp(argv[1], "account") == 0)
        rc = pam_acct_mgmt(handle, 0);
    else if (strcmp(argv[1], "session") == 0) {
        rc = pam_setcred(handle, PAM_ESTABLISH_CRED);
        if (rc == PAM_SUCCESS)
            rc = pam_open_session(handle, 0);
        if (rc == PAM_SUCCESS)
            rc = pam_close_session(handle, 0);
    } else if (strcmp(argv[1], "chauthtok") == 0)
        rc = pam_chauthtok(handle, 0);
    else
        return 2;
    printf("%s rc=%d name=%s password_prompts=%d\n", argv[1], rc, pam_strerror(handle, rc), echo_off_requests);
    pam_end(handle, rc);
    return 0;
}
