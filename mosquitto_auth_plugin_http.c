#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <curl/curl.h>

#include <mosquitto.h>
#include <mosquitto_plugin.h>

#define DEFAULT_USER_URI "http://localhost:5000/mqtt-user"
#define DEFAULT_ACL_URI "http://localhost:5000/mqtt-acl"

static char *http_user_uri = NULL;
static char *http_acl_uri = NULL;

int mosquitto_auth_plugin_version(void) {
  return MOSQ_AUTH_PLUGIN_VERSION;
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count) {
  int i = 0;
  for (i = 0; i < auth_opt_count; i++) {
#ifdef MQAP_DEBUG
    fprintf(stderr, "AuthOptions: key=%s, val=%s\n", auth_opts[i].key, auth_opts[i].value);
#endif
    if (strncmp(auth_opts[i].key, "http_user_uri", 13) == 0) {
      http_user_uri = auth_opts[i].value;
    }
    if (strncmp(auth_opts[i].key, "http_acl_uri", 12) == 0) {
      http_acl_uri = auth_opts[i].value;
    }
  }
  if (http_user_uri == NULL) {
    http_user_uri = DEFAULT_USER_URI;
  }
  if (http_acl_uri == NULL) {
    http_acl_uri = DEFAULT_ACL_URI;
  }
  mosquitto_log_printf(MOSQ_LOG_INFO, "http_user_uri = %s, http_acl_uri = %s", http_user_uri, http_acl_uri);
#ifdef MQAP_DEBUG
    fprintf(stderr, "http_user_uri = %s, http_acl_uri = %s\n", http_user_uri, http_acl_uri);
#endif
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count) {
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload) {
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload) {
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_unpwd_check(void *user_data, const char *username, const char *password) {
  if (username == NULL || password == NULL) {
    return MOSQ_ERR_AUTH;
  }
#ifdef MQAP_DEBUG
  fprintf(stderr, "mosquitto_auth_unpwd_check: username=%s, password=%s\n", username, password);
#endif
  mosquitto_log_printf(MOSQ_LOG_DEBUG, "mosquitto_auth_unpwd_check: username=%s, password=%s", username, password);

  int rc;
  int rv;
  CURL *ch;

  if ((ch = curl_easy_init()) == NULL) {
    mosquitto_log_printf(MOSQ_LOG_WARNING, "failed to initialize curl (curl_easy_init AUTH): %s", strerror(errno));
#ifdef MQAP_DEBUG
    fprintf(stderr, "malloc(): %s [%s, %d]\n", strerror(errno), __FILE__, __LINE__);
#endif
    return MOSQ_ERR_AUTH;
  }

  char *escaped_username;
  char *escaped_password;
  escaped_username = curl_easy_escape(ch, username, 0);
  escaped_password = curl_easy_escape(ch, password, 0);
  size_t data_len = strlen("username=&password=") + strlen(escaped_username) + strlen(escaped_password) + 1;
  char* data = NULL;
  if ((data = malloc(data_len)) == NULL) { 
	mosquitto_log_printf(MOSQ_LOG_WARNING, "failed allocate data memory (%u): %s", data_len, strerror(errno));
#ifdef MQAP_DEBUG
    	fprintf(stderr, "malloc(): %s [%s, %d]\n", strerror(errno), __FILE__, __LINE__);
#endif
	rv = -1;
  } else {
	memset(data, 0, data_len);
  	snprintf(data, data_len, "username=%s&password=%s", escaped_username, escaped_password);

  	curl_easy_setopt(ch, CURLOPT_POST, 1L);
  	curl_easy_setopt(ch, CURLOPT_URL, http_user_uri);
  	curl_easy_setopt(ch, CURLOPT_POSTFIELDS, data);
  	curl_easy_setopt(ch, CURLOPT_POSTFIELDSIZE, strlen(data));

  	if ((rv = curl_easy_perform(ch)) == CURLE_OK) {
    		curl_easy_getinfo(ch, CURLINFO_RESPONSE_CODE, &rc);
    		rv = rc;
  	} else {
#ifdef MQAP_DEBUG
    		fprintf(stderr, "%s\n", curl_easy_strerror(rv));
#endif
    		rv = -1;
  	}
  }
  curl_free(escaped_username);
  curl_free(escaped_password);
  curl_easy_cleanup(ch);
  free(data);
  data = NULL;
  if (rv == -1) {
    return MOSQ_ERR_AUTH;
  }
#ifdef MQAP_DEBUG
  if (rc != 200) {
    fprintf(stderr, "HTTP response code = %d\n", rc);
  }
#endif
  mosquitto_log_printf(MOSQ_LOG_DEBUG, "HTTP response code = %d", rc);

  return (rc == 200 ? MOSQ_ERR_SUCCESS : MOSQ_ERR_AUTH);
}

int mosquitto_auth_acl_check(void *user_data, const char *clientid, const char *username, const char *topic, int access) {
  if (username == NULL) {
    // If the username is NULL then it's an anonymous user, currently we let
    // this pass assuming the admin will disable anonymous users if required.
    return MOSQ_ERR_SUCCESS;
  }

  char access_name[6];
  if (access == MOSQ_ACL_READ) {
    sprintf(access_name, "read");
  } else if (access == MOSQ_ACL_WRITE) {
    sprintf(access_name, "write");
  } else {
    sprintf(access_name, "none");
  }

#ifdef MQAP_DEBUG
  fprintf(stderr, "mosquitto_auth_acl_check: clientid=%s, username=%s, topic=%s, access=%s\n",
    clientid, username, topic, access_name);
#endif
  mosquitto_log_printf(MOSQ_LOG_DEBUG, "mosquitto_auth_acl_check: clientid=%s, username=%s, topic=%s, access=%s", 
    clientid, username, topic, access_name);

  int rc;
  int rv;
  CURL *ch;

  if ((ch = curl_easy_init()) == NULL) {
     mosquitto_log_printf(MOSQ_LOG_WARNING, "failed to initialize curl (curl_easy_init ACL): %s", strerror(errno));
#ifdef MQAP_DEBUG
    fprintf(stderr, "malloc(): %s [%s, %d]\n", strerror(errno), __FILE__, __LINE__);
#endif
    return MOSQ_ERR_ACL_DENIED;
  }

  char *escaped_clientid;
  char *escaped_username;
  char *escaped_topic;
  escaped_clientid = curl_easy_escape(ch, clientid, 0);
  escaped_username = curl_easy_escape(ch, username, 0);
  escaped_topic = curl_easy_escape(ch, topic, 0);
  size_t data_len = strlen("clientid=&username=&topic=&access=") + strlen(escaped_clientid) + strlen(escaped_username) + strlen(escaped_topic) + strlen(access_name) + 1;
  char* data = NULL;
  if ((data = malloc(data_len)) == NULL) { 
	mosquitto_log_printf(MOSQ_LOG_WARNING, "failed allocate data memory (%u): %s", data_len, strerror(errno));
#ifdef MQAP_DEBUG
    	fprintf(stderr, "malloc(): %s [%s, %d]\n", strerror(errno), __FILE__, __LINE__);
#endif
	rv = -1;
  } else {
	memset(data, 0, data_len);
  	snprintf(data, data_len, "clientid=%s&username=%s&topic=%s&access=%s",
    		escaped_clientid, escaped_username, escaped_topic, access_name);
	curl_easy_setopt(ch, CURLOPT_POST, 1L);
	curl_easy_setopt(ch, CURLOPT_URL, http_acl_uri);
	curl_easy_setopt(ch, CURLOPT_POSTFIELDS, data);
	curl_easy_setopt(ch, CURLOPT_POSTFIELDSIZE, strlen(data));

  	if ((rv = curl_easy_perform(ch)) == CURLE_OK) {
	    curl_easy_getinfo(ch, CURLINFO_RESPONSE_CODE, &rc);
	    rv = rc;
	} else {
#ifdef MQAP_DEBUG
	    fprintf(stderr, "%s\n", curl_easy_strerror(rv));
#endif
	    rv = -1;
	}
  }
  curl_free(escaped_clientid);
  curl_free(escaped_username);
  curl_free(escaped_topic);
  curl_easy_cleanup(ch);
  free(data);
  data = NULL;
  if (rv == -1) {
    return MOSQ_ERR_ACL_DENIED;
  }
#ifdef MQAP_DEBUG
  if (rc != 200) {
    fprintf(stderr, "HTTP response code = %d\n", rc);
  }
#endif
  mosquitto_log_printf(MOSQ_LOG_DEBUG, "HTTP response code = %d", rc);

  return (rc == 200 ? MOSQ_ERR_SUCCESS : MOSQ_ERR_ACL_DENIED);
}

int mosquitto_auth_psk_key_get(void *user_data, const char *hint, const char *identity, char *key, int max_key_len) {
  return MOSQ_ERR_AUTH;
}

