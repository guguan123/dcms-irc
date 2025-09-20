#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <curl/curl.h>
#include <jansson.h>
#include <time.h>
#include <pthread.h>
#include <ini.h>

// 配置结构体
typedef struct {
	char *irc_server;       // IRC 服务器地址
	int irc_port;           // IRC 服务器端口
	char *irc_nick;         // IRC 昵称
	char *irc_user;         // IRC 用户名
	char *irc_realname;     // IRC 真实姓名
	char *irc_channel;      // IRC 频道
	char *website_api_url;  // 网站 API 地址
	char *website_user;     // 网站用户名
	char *website_pass;     // 网站密码
	char *cookie_file;      // Cookie 文件路径
	int website_room;       // 网站聊天室 ID
	int poll_interval;      // 轮询间隔（秒）
	int use_tls;            // 是否使用 TLS (0 = 不使用, 1 = 使用)
	char **bridge_users;    // 桥接 IRC 用户列表
	int bridge_users_count; // 桥接用户数量
} Config;

// 全局变量
SSL *irc_ssl = NULL;	// IRC TLS 连接
int irc_sock = -1;		// IRC 套接字
int last_msg_id = 0;	// 最后处理的消息 ID
int dcms_user_id;		// 保存自己的用户ID
const char *ignore_prefixes[] = {"//", ";", NULL};				// 忽略的前缀
pthread_mutex_t curl_mutex = PTHREAD_MUTEX_INITIALIZER;			// CURL 互斥锁
pthread_mutex_t last_msg_id_mutex = PTHREAD_MUTEX_INITIALIZER;	// 变量 last_msg_id 互斥锁

// CURL 响应缓冲区
struct MemoryStruct {
	char *memory;
	size_t size;
};

// 辅助函数，安全地更新 last_msg_id
void update_last_msg_id(int new_id) {
	pthread_mutex_lock(&last_msg_id_mutex);
	if (new_id > last_msg_id) {
		last_msg_id = new_id;
		printf("Updated last_msg_id to %d\n", last_msg_id);
	}
	pthread_mutex_unlock(&last_msg_id_mutex);
}

// CURL 写回调函数
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;
	char *ptr = realloc(mem->memory, mem->size + realsize + 1);
	if (!ptr) {
		printf("Not enough memory\n");
		return 0;
	}
	mem->memory = ptr;
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;
	return realsize;
}

// INI 配置解析器
static int config_ini_handler(void *user, const char *section, const char *name, const char *value) {
	Config *config = (Config *)user;
	if (strcmp(section, "irc") == 0) {
		if (strcmp(name, "server") == 0) config->irc_server = strdup(value);
		else if (strcmp(name, "port") == 0) config->irc_port = atoi(value);
		else if (strcmp(name, "nick") == 0) config->irc_nick = strdup(value);
		else if (strcmp(name, "user") == 0) config->irc_user = strdup(value);
		else if (strcmp(name, "realname") == 0) config->irc_realname = strdup(value);
		else if (strcmp(name, "channel") == 0) config->irc_channel = strdup(value);
		else if (strcmp(name, "use_tls") == 0) config->use_tls = atoi(value);
		else if (strcmp(name, "bridge_users") == 0) {
			// 用逗号拆分受信任的用户
			char *value_copy = strdup(value);
			char *token = strtok(value_copy, ",");
			config->bridge_users_count = 0;
			while (token) {
				config->bridge_users_count++;
				token = strtok(NULL, ",");
			}
			config->bridge_users = malloc(config->bridge_users_count * sizeof(char *));
			token = strtok(strdup(value), ",");
			for (int i = 0; token && i < config->bridge_users_count; i++) {
				config->bridge_users[i] = strdup(token);
				token = strtok(NULL, ",");
			}
			free(value_copy);
		}
	} else if (strcmp(section, "website") == 0) {
		if (strcmp(name, "api_url") == 0) config->website_api_url = strdup(value);
		else if (strcmp(name, "user") == 0) config->website_user = strdup(value);
		else if (strcmp(name, "pass") == 0) config->website_pass = strdup(value);
		else if (strcmp(name, "room") == 0) config->website_room = atoi(value);
		else if (strcmp(name, "poll_interval") == 0) config->poll_interval = atoi(value);
		else if (strcmp(name, "cookie_file") == 0) config->cookie_file = strdup(value);
	}
	return 1;
}

// 加载配置文件
int load_config(const char *filename, Config *config) {
	if (ini_parse(filename, config_ini_handler, config) < 0) {
		fprintf(stderr, "Failed to load config file %s\n", filename);
		return -1;
	}
	return 0;
}

// 释放配置内存
void free_config(Config *config) {
	free(config->irc_server);
	free(config->irc_nick);
	free(config->irc_user);
	free(config->irc_realname);
	free(config->irc_channel);
	free(config->website_api_url);
	free(config->website_user);
	free(config->website_pass);
	free(config->cookie_file);
	for (int i = 0; i < config->bridge_users_count; i++) {
		free(config->bridge_users[i]);
	}
	free(config->bridge_users);
}

// 初始化 OpenSSL 上下文
SSL_CTX *init_ssl_context() {
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
	if (!ctx) {
		fprintf(stderr, "SSL_CTX_new failed\n");
		return NULL;
	}
	SSL_CTX_set_default_verify_paths(ctx); // 自动加载系统 CA 路径
	return ctx;
}

// 连接到 IRC 服务器
int connect_irc_server(const Config *config) {
	struct addrinfo hints, *res, *p;
	char port_str[16];
	int sock = -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC; // 支持 IPv4 和 IPv6
	hints.ai_socktype = SOCK_STREAM;

	snprintf(port_str, sizeof(port_str), "%d", config->irc_port);

	int status = getaddrinfo(config->irc_server, port_str, &hints, &res);
	if (status != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
		return -1;
	}

	for (p = res; p != NULL; p = p->ai_next) {
		sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (sock < 0) continue;
		if (connect(sock, p->ai_addr, p->ai_addrlen) == 0) break;
		close(sock);
		sock = -1;
	}
	freeaddrinfo(res);

	if (sock < 0) {
		perror("Connection failed");
		return -1;
	}
	irc_sock = sock;

	if (config->use_tls) {
		SSL_CTX *ctx = init_ssl_context();
		if (!ctx) {
			close(irc_sock);
			return -1;
		}

		irc_ssl = SSL_new(ctx);
		if (!irc_ssl) {
			fprintf(stderr, "SSL_new failed\n");
			SSL_CTX_free(ctx);
			close(irc_sock);
			return -1;
		}

		SSL_set_fd(irc_ssl, irc_sock);
		if (SSL_connect(irc_ssl) <= 0) {
			ERR_print_errors_fp(stderr);
			SSL_free(irc_ssl);
			SSL_CTX_free(ctx);
			close(irc_sock);
			return -1;
		}

		if (SSL_get_verify_result(irc_ssl) != X509_V_OK) {
			fprintf(stderr, "Certificate verification failed\n");
			SSL_free(irc_ssl);
			SSL_CTX_free(ctx);
			close(irc_sock);
			return -1;
		}

		SSL_CTX_free(ctx);
		printf("TLS connection to %s:%d established\n", config->irc_server, config->irc_port);
	} else {
		printf("Plain TCP connection to %s:%d established\n", config->irc_server, config->irc_port);
	}

	return 0;
}

pthread_mutex_t irc_send_mutex = PTHREAD_MUTEX_INITIALIZER; // IRC的互斥锁
// 发送 IRC 命令
void send_irc_command(const Config *config, const char *cmd) {
	char buffer[512];
	snprintf(buffer, sizeof(buffer), "%s\r\n", cmd);
	pthread_mutex_lock(&irc_send_mutex); // 加锁
	if (config->use_tls) {
		if (SSL_write(irc_ssl, buffer, strlen(buffer)) <= 0) {
			ERR_print_errors_fp(stderr);
		}
	} else {
		if (send(irc_sock, buffer, strlen(buffer), 0) < 0) {
			perror("Send failed");
		}
	}
	pthread_mutex_unlock(&irc_send_mutex); // 解锁
	printf("Sent: %s", buffer);
}

// 登录到网站 API
int login_to_website(const Config *config) {
	CURL *curl = curl_easy_init();
	if (!curl) return -1;

	struct MemoryStruct chunk;
	chunk.memory = malloc(1);
	chunk.size = 0;

	char post_data[256];
	snprintf(post_data, sizeof(post_data), "nick=%s&password=%s&aut_save=0", config->website_user, config->website_pass);
	char url[512];
	snprintf(url, sizeof(url), "%s?action=login", config->website_api_url);

	pthread_mutex_lock(&curl_mutex);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
	curl_easy_setopt(curl, CURLOPT_COOKIEFILE, config->cookie_file);
	curl_easy_setopt(curl, CURLOPT_COOKIEJAR, config->cookie_file);
	curl_easy_setopt(curl, CURLOPT_COOKIESESSION, 1L); // 启动新的 Cookie 会话

	CURLcode res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		free(chunk.memory);
		curl_easy_cleanup(curl);
		pthread_mutex_unlock(&curl_mutex);
		return -1;
	}

	long http_code;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	if (http_code != 200) {
		fprintf(stderr, "HTTP error: %ld\n", http_code);
		free(chunk.memory);
		curl_easy_cleanup(curl);
		pthread_mutex_unlock(&curl_mutex);
		return -1;
	}

	json_error_t error;
	json_t *root = json_loads(chunk.memory, 0, &error);
	if (!root) {
		fprintf(stderr, "JSON parse error: %s\n", error.text);
		free(chunk.memory);
		curl_easy_cleanup(curl);
		pthread_mutex_unlock(&curl_mutex);
		return -1;
	}

	const char *status = json_string_value(json_object_get(root, "status"));
	if (strcmp(status, "success") != 0) {
		fprintf(stderr, "Website login failed: %s\n", json_string_value(json_object_get(root, "message")));
		json_decref(root);
		free(chunk.memory);
		curl_easy_cleanup(curl);
		pthread_mutex_unlock(&curl_mutex);
		return -1;
	}

	// 提取 user_id
	json_t *data = json_object_get(root, "data");
	json_t *user_id_json = json_object_get(data, "user_id");
	if (json_is_integer(user_id_json)) {
		dcms_user_id = json_integer_value(user_id_json); // 赋值给全局变量
		printf("Stored user_id: %d\n", dcms_user_id);
	} else {
		fprintf(stderr, "Failed to parse user_id from login response\n");
		json_decref(root);
		free(chunk.memory);
		curl_easy_cleanup(curl);
		pthread_mutex_unlock(&curl_mutex);
		return -1;
	}

	printf("Website login successful\n");
	json_decref(root);
	free(chunk.memory);
	curl_easy_cleanup(curl);
	pthread_mutex_unlock(&curl_mutex);
	return 0;
}

// 消息前缀检查
int should_ignore_message(const char *msg) {
	if (!msg) return 0;
	for (int i = 0; ignore_prefixes[i] != NULL; i++) {
		if (strncmp(msg, ignore_prefixes[i], strlen(ignore_prefixes[i])) == 0) {
			return 1;
		}
	}
	return 0;
}

// 向网站发送消息
int post_to_website(const Config *config, const char *msg) {
	CURL *curl = curl_easy_init();
	if (!curl) return -1;

	struct MemoryStruct chunk;
	chunk.memory = malloc(1);
	chunk.size = 0;

	char post_data[512];
	snprintf(post_data, sizeof(post_data), "msg=%s", msg);
	char url[512];
	snprintf(url, sizeof(url), "%s?action=chat-msg-add&room=%d", config->website_api_url, config->website_room);

	pthread_mutex_lock(&curl_mutex);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
	curl_easy_setopt(curl, CURLOPT_COOKIEFILE, config->cookie_file);
	curl_easy_setopt(curl, CURLOPT_COOKIEJAR, config->cookie_file);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

	CURLcode res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		free(chunk.memory);
		curl_easy_cleanup(curl);
		pthread_mutex_unlock(&curl_mutex);
		return -1;
	}

	long http_code;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	if (http_code == 401 || http_code == 403) {
		fprintf(stderr, "Session expired, attempting re-login\n");
		free(chunk.memory);
		curl_easy_cleanup(curl);
		pthread_mutex_unlock(&curl_mutex);
		if (login_to_website(config) == 0) {
			// 重新登录后重试
			//return post_to_website(config, msg);
		}
		return -1;
	}

	json_error_t error;
	json_t *root = json_loads(chunk.memory, 0, &error);
	if (!root) {
		fprintf(stderr, "JSON parse error: %s\n", error.text);
		free(chunk.memory);
		curl_easy_cleanup(curl);
		pthread_mutex_unlock(&curl_mutex);
		return -1;
	}

	const char *status = json_string_value(json_object_get(root, "status"));
	if (strcmp(status, "success") != 0) {
		const char *message = json_string_value(json_object_get(root, "message"));
		fprintf(stderr, "Post to website failed: %s\n", message);
		if (strstr(message, "not logged in") || strstr(message, "session")) {
			fprintf(stderr, "Session invalid, attempting re-login\n");
			json_decref(root);
			free(chunk.memory);
			curl_easy_cleanup(curl);
			pthread_mutex_unlock(&curl_mutex);
			if (login_to_website(config) == 0) {
				// 重新登录后重试
				//return post_to_website(config, msg);
			}
			return -1;
		}
		json_decref(root);
		free(chunk.memory);
		curl_easy_cleanup(curl);
		pthread_mutex_unlock(&curl_mutex);
		return -1;
	}

	// 更新 last_msg_id
	const char *msg_id = json_string_value(json_object_get(root, "id"));
	if (msg_id != NULL) {
		char* endptr;
		long received_id = strtol(msg_id, &endptr, 10); // 尝试将字符串转换为整数
		// 检查是否成功转换
		if (*endptr == '\0') {
			update_last_msg_id((int)received_id); // 更新最后的消息ID
		} else {
			fprintf(stderr, "ID is not a valid integer\n");
		}
	} else {
		fprintf(stderr, "ID not found in the response\n");
	}

	json_decref(root);
	free(chunk.memory);
	curl_easy_cleanup(curl);
	pthread_mutex_unlock(&curl_mutex);
	return 0;
}

// 获取DCMS用户昵称
char *get_dcms_user_nick(const Config *config, int user_id) {
	CURL *curl = curl_easy_init();
	if (!curl) return NULL;

	struct MemoryStruct chunk;
	chunk.memory = malloc(1);
	chunk.size = 0;

	char url[512];
	snprintf(url, sizeof(url), "%s?action=user-info&id=%d", config->website_api_url, user_id);

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_COOKIEFILE, config->cookie_file);
	curl_easy_setopt(curl, CURLOPT_COOKIEJAR, config->cookie_file);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

	CURLcode res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed for user-info: %s\n", curl_easy_strerror(res));
		free(chunk.memory);
		curl_easy_cleanup(curl);
		return NULL;
	}

	long http_code;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	if (http_code == 401 || http_code == 403) {
		fprintf(stderr, "Session expired for user-info, attempting re-login\n");
		free(chunk.memory);
		curl_easy_cleanup(curl);
		return NULL;
	}

	json_error_t error;
	json_t *root = json_loads(chunk.memory, 0, &error);
	if (!root) {
		fprintf(stderr, "JSON parse error for user-info: %s\n", error.text);
		free(chunk.memory);
		curl_easy_cleanup(curl);
		return NULL;
	}

	const char *status = json_string_value(json_object_get(root, "status"));
	if (strcmp(status, "success") != 0) {
		fprintf(stderr, "Failed to get user info: %s\n", json_string_value(json_object_get(root, "message")));
		json_decref(root);
		free(chunk.memory);
		curl_easy_cleanup(curl);
		return NULL;
	}

	json_t *data = json_object_get(root, "data");
	const char *nick = json_string_value(json_object_get(data, "nick"));
	char *nick_copy = nick ? strdup(nick) : NULL;

	json_decref(root);
	free(chunk.memory);
	curl_easy_cleanup(curl);
	return nick_copy;
}

// 轮询网站获取新消息
void *poll_website(void *arg) {
	Config *config = (Config *)arg;

	// Initial fetch to get the latest message ID
	CURL *curl = curl_easy_init();
	if (!curl) {
		sleep(config->poll_interval);
		return NULL;
	}

	struct MemoryStruct chunk;
	chunk.memory = malloc(1);
	chunk.size = 0;

	char url[512];
	snprintf(url, sizeof(url), "%s?action=chat-msg-list&room=%d&page=1", config->website_api_url, config->website_room);

	pthread_mutex_lock(&curl_mutex);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_COOKIEFILE, config->cookie_file);
	curl_easy_setopt(curl, CURLOPT_COOKIEJAR, config->cookie_file);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

	CURLcode res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		free(chunk.memory);
		curl_easy_cleanup(curl);
		pthread_mutex_unlock(&curl_mutex);
		sleep(config->poll_interval);
		return NULL;
	}

	long http_code;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	if (http_code == 401 || http_code == 403) {
		fprintf(stderr, "Session expired, attempting re-login\n");
		free(chunk.memory);
		curl_easy_cleanup(curl);
		pthread_mutex_unlock(&curl_mutex);
		if (login_to_website(config) == 0) {
			return NULL; // 在下一个线程启动时重试
		}
		sleep(config->poll_interval);
		return NULL;
	}

	json_error_t error;
	json_t *root = json_loads(chunk.memory, 0, &error);
	if (!root) {
		fprintf(stderr, "JSON parse error: %s\n", chunk.memory);
		free(chunk.memory);
		curl_easy_cleanup(curl);
		pthread_mutex_unlock(&curl_mutex);
		sleep(config->poll_interval);
		return NULL;
	}

	const char *status = json_string_value(json_object_get(root, "status"));
	if (strcmp(status, "success") == 0) {
		json_t *data = json_object_get(root, "data");
		size_t index;
		json_t *value;
		json_array_foreach(data, index, value) {
			int id = json_integer_value(json_object_get(value, "id"));
			update_last_msg_id(id);
		}
	}

	json_decref(root);
	free(chunk.memory);
	curl_easy_cleanup(curl);
	pthread_mutex_unlock(&curl_mutex);

	// 使用 chat-msg-get API获取新消息
	while (1) {
		curl = curl_easy_init();
		if (!curl) {
			sleep(config->poll_interval);
			continue;
		}

		chunk.memory = malloc(1);
		chunk.size = 0;

		int current_last_msg_id = last_msg_id;
		snprintf(url, sizeof(url), "%s?action=chat-msg-get&room=%d&id=%d", config->website_api_url, config->website_room, current_last_msg_id);

		pthread_mutex_lock(&curl_mutex);
		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_COOKIEFILE, config->cookie_file);
		curl_easy_setopt(curl, CURLOPT_COOKIEJAR, config->cookie_file);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

		res = curl_easy_perform(curl);
		if (res != CURLE_OK) {
			fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
			free(chunk.memory);
			curl_easy_cleanup(curl);
			pthread_mutex_unlock(&curl_mutex);
			sleep(config->poll_interval);
			continue;
		}

		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
		if (http_code == 401 || http_code == 403) {
			fprintf(stderr, "Session expired, attempting re-login\n");
			free(chunk.memory);
			curl_easy_cleanup(curl);
			pthread_mutex_unlock(&curl_mutex);
			if (login_to_website(config) == 0) {
				continue; // 重新登录后重试
			}
			sleep(config->poll_interval);
			continue;
		}

		root = json_loads(chunk.memory, 0, &error);
		if (!root) {
			fprintf(stderr, "JSON parse error: %s\n", chunk.memory);
			free(chunk.memory);
			curl_easy_cleanup(curl);
			pthread_mutex_unlock(&curl_mutex);
			sleep(config->poll_interval);
			continue;
		}

		status = json_string_value(json_object_get(root, "status"));
		if (strcmp(status, "success") == 0) {
			json_t *data = json_object_get(root, "data");
			size_t index;
			json_t *value;
			json_array_foreach(data, index, value) {
				int id = json_integer_value(json_object_get(value, "id"));
				int id_user = json_integer_value(json_object_get(value, "id_user"));
				// 忽略自己的消息
				if (id_user == dcms_user_id) {
					update_last_msg_id(id);
					continue;
				}
				if (id > current_last_msg_id) {
					const char *msg = json_string_value(json_object_get(value, "msg"));
					if (should_ignore_message(msg)) {
						printf("Ignoring website message (filtered): %s\n", msg);
						update_last_msg_id(id);
						continue;
					}
					char *nick = get_dcms_user_nick(config, id_user);
					char irc_msg[512];
					if (nick) {
						snprintf(irc_msg, sizeof(irc_msg), "PRIVMSG %s :[DCMS] %s: %s", config->irc_channel, nick, msg);
						free(nick);
					} else {
						snprintf(irc_msg, sizeof(irc_msg), "PRIVMSG %s :[DCMS] User%d: %s", config->irc_channel, id_user, msg);
					}
					send_irc_command(config, irc_msg);
					update_last_msg_id(id);
				}
			}
		} else {
			const char *message = json_string_value(json_object_get(root, "message"));
			if (strstr(message, "not logged in") || strstr(message, "session") || strstr(message, "room id not found") || strstr(message, "room not found") || strstr(message, "msg id not found")) {
				fprintf(stderr, "Session invalid or invalid parameters, attempting re-login\n");
				json_decref(root);
				free(chunk.memory);
				curl_easy_cleanup(curl);
				pthread_mutex_unlock(&curl_mutex);
				if (login_to_website(config) == 0) {
					continue; // 重新登录后重试
				}
			}
		}

		json_decref(root);
		free(chunk.memory);
		curl_easy_cleanup(curl);
		pthread_mutex_unlock(&curl_mutex);
		sleep(config->poll_interval);
	}
	return NULL;
}

// 检查是否为可信用户
int is_bridge_user(const Config *config, const char *nick) {
	for (int i = 0; i < config->bridge_users_count; i++) {
		if (strcmp(config->bridge_users[i], nick) == 0) {
			return 1;
		}
	}
	return 0;
}

// 处理 IRC 消息
void *handle_irc(void *arg) {
	Config *config = (Config *)arg;
	char buffer[512];
	int joined = 0;
	while (1) {
		int bytes;
		if (config->use_tls) {
			bytes = SSL_read(irc_ssl, buffer, sizeof(buffer) - 1);
			if (bytes <= 0) {
				ERR_print_errors_fp(stderr);
				break;
			}
		} else {
			bytes = recv(irc_sock, buffer, sizeof(buffer) - 1, 0);
			if (bytes <= 0) {
				perror("Receive failed");
				break;
			}
		}
		buffer[bytes] = '\0';
		printf("Received: %s", buffer);

		// 检查 001 响应，收到后再 JOIN
		if (!joined && strstr(buffer, " 001 ")) {
			char join_cmd[512];
			snprintf(join_cmd, sizeof(join_cmd), "JOIN %s", config->irc_channel);
			send_irc_command(config, join_cmd);
			joined = 1;
		}

		if (strstr(buffer, "PING")) {
			char *ping_ptr = strstr(buffer, "PING");
			if (ping_ptr) {
				char *param = strchr(ping_ptr, ':');
				if (param) {
					char pong[512];
					snprintf(pong, sizeof(pong), "PONG :%s\r\n", param + 1); // 保留冒号后的内容
					send_irc_command(config, pong);
				}
			}
		} else if (strstr(buffer, "PRIVMSG")) {
			// 提取发送者昵称
			if (buffer[0] != ':') {
				fprintf(stderr, "Invalid PRIVMSG format: missing ':'\n");
				continue;
			}

			char nick[256] = {0};
			char *nick_start = buffer + 1; // 跳过开头的 ':'
			char *nick_end = strchr(nick_start, '!');
			if (!nick_end) {
				fprintf(stderr, "Invalid PRIVMSG format: missing '!'\n");
				continue;
			}

			// 复制昵称到临时缓冲区
			size_t nick_len = nick_end - nick_start;
			if (nick_len >= sizeof(nick)) {
				fprintf(stderr, "Nickname too long\n");
				continue;
			}
			strncpy(nick, nick_start, nick_len);
			nick[nick_len] = '\0';

			// 提取消息内容
			char *msg_start = strstr(buffer, " :");
			if (!msg_start) {
				fprintf(stderr, "Invalid PRIVMSG format: missing message content\n");
				continue;
			}
			msg_start += 2; // 跳过 " :"
			char *msg_end = strstr(msg_start, "\r\n");
			if (!msg_end) {
				fprintf(stderr, "Invalid PRIVMSG format: missing \\r\\n\n");
				continue;
			}

			// 复制消息内容到临时缓冲区
			char message[256] = {0};
			size_t msg_len = msg_end - msg_start;
			if (msg_len >= sizeof(message)) {
				fprintf(stderr, "Message too long\n");
				continue;
			}
			strncpy(message, msg_start, msg_len);
			message[msg_len] = '\0';

			// 检查是否为目标频道
			if (strstr(buffer, config->irc_channel)) {
				// 跳过以指定字符串开头的消息
				if (should_ignore_message(message)) {
					printf("Ignoring IRC message (filtered): %s\n", message);
					continue;
				}
				// 构造消息格式，检查是否为可信用户
				char *formatted_msg = NULL;
				if (is_bridge_user(config, nick)) {
					// 只发消息内容
					formatted_msg = strdup(message);
				} else {
					// 先计算所需长度
					int needed = snprintf(NULL, 0, "[IRC] %s: %s", nick, message) + 1;
					formatted_msg = malloc(needed);
					if (formatted_msg) {
						snprintf(formatted_msg, needed, "[IRC] %s: %s", nick, message);
					}
				}
				if (formatted_msg) {
					post_to_website(config, formatted_msg);
					free(formatted_msg);
				}
			}
		}
	}
	return NULL;
}

int main() {
	// 加载配置
	Config config = {0};
	if (load_config("config.ini", &config) != 0) {
		fprintf(stderr, "Failed to load configuration\n");
		return 1;
	}

	// 初始化 CURL
	curl_global_init(CURL_GLOBAL_ALL);

	// 登录网站
	printf("Login to DCMS...\n");
	if (login_to_website(&config) != 0) {
		fprintf(stderr, "Failed to login to DCMS\n");
		free_config(&config);
		curl_global_cleanup();
		return 1;
	}

	// 连接 IRC 服务器
	printf("Connect to IRC...\n");
	if (connect_irc_server(&config) != 0) {
		fprintf(stderr, "Failed to connect to IRC server\n");
		free_config(&config);
		curl_global_cleanup();
		return 1;
	}

	// IRC 登录，发送 NICK 和 USER
	char nick_cmd[512], user_cmd[512];
	snprintf(nick_cmd, sizeof(nick_cmd), "NICK %s", config.irc_nick);
	snprintf(user_cmd, sizeof(user_cmd), "USER %s 0 * :%s", config.irc_user, config.irc_realname);
	send_irc_command(&config, nick_cmd);
	send_irc_command(&config, user_cmd);

	// 启动线程
	pthread_t irc_thread, website_thread;
	pthread_create(&irc_thread, NULL, handle_irc, &config);
	pthread_create(&website_thread, NULL, poll_website, &config);

	// 等待线程结束
	pthread_join(irc_thread, NULL);
	pthread_join(website_thread, NULL);

	// 清理资源
	if (config.use_tls) {
		SSL_shutdown(irc_ssl);
		SSL_free(irc_ssl);
	}
	close(irc_sock);
	free_config(&config);
	curl_global_cleanup();
	pthread_mutex_destroy(&curl_mutex);
	return 0;
}
