#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <arpa/inet.h>
#define SOCK_PATH "/tmp/afl-definition-monitor"
#define MAX_BUF 0x100
enum protocol { FTP, RTSP, DTLS, SSH, TLS };

int __fstate_shm_id;
char *__fstate_shm_ptr, *__fstate_shm_base;
int __mstate_shm_id;
char *__mstate_shm_ptr;
int unix_sock;
int bucket_size;
int bucket_index;

int create_new_bucket() {
  __fstate_shm_ptr += (bucket_size + 4);
  return 0;
}

int check_getenv(char *key, char *value) {
#ifdef STATEAFL_CLIENT
  if (!strcmp(key, "SHM_STATE_ENV_VAR")) {
    __mstate_shm_id = atoi(value);
    return 0;
  }
#endif
#ifdef NSFUZZ_CLIENT
  if (!strcmp(key, "__AFL_STATE_SHM_ID")) {
    __mstate_shm_id = atoi(value);
    return 0;
  }
#endif
  return -1;
}

int check_shmat(int shm_id, char *result) {
  if (shm_id == __mstate_shm_id) {
    __mstate_shm_ptr = result;
    return 0;
  }
  return -1;
}

#define HASH_CONST 0xa5b35705
#define ROL64(_x, _r)                                                          \
  ((((unsigned long long)(_x)) << (_r)) |                                      \
   (((unsigned long long)(_x)) >> (64 - (_r))))

int hash32(const void *key, unsigned int len, unsigned int seed) {

  const unsigned long long *data = (unsigned long long *)key;
  unsigned long long h1 = seed ^ len;

  len >>= 3;

  while (len--) {

    unsigned long long k1 = *data++;

    k1 *= 0x87c37b91114253d5ULL;
    k1 = ROL64(k1, 31);
    k1 *= 0x4cf5ad432745937fULL;

    h1 ^= k1;
    h1 = ROL64(h1, 27);
    h1 = h1 * 5 + 0x52dce729;
  }

  h1 ^= h1 >> 33;
  h1 *= 0xff51afd7ed558ccdULL;
  h1 ^= h1 >> 33;
  h1 *= 0xc4ceb9fe1a85ec53ULL;
  h1 ^= h1 >> 33;

  return h1;
}

long long update_sutstate_dump(int state_code) {
  char tmp[0x20];
  int r;
  int hash_code;
#ifdef STATEAFL_CLIENT
  memset(tmp, 0x0, 0x20);
  memcpy(tmp, "sync\0", 0x5);
  *(int *)(&tmp[5]) = ++bucket_index;
  *(int *)(&tmp[9]) = state_code;
  write(unix_sock, tmp, 13);
  r = read(unix_sock, tmp, sizeof(tmp));
  if (r <= 0 || strcmp(tmp, "ok")) {
    exit(1);
  }

#endif
  printf("here! youwant to sync?\n");
#ifdef NSFUZZ_CLIENT
  if (!__mstate_shm_ptr) {
    exit(1);
  }
  printf("entered here\n");
  hash_code = hash32(__mstate_shm_ptr, (1 << 16), HASH_CONST);
  memset(tmp, 0x0, 0x20);
  memcpy(tmp, "sync\0", 0x5);
  *(int *)(&tmp[5]) = ++bucket_index;
  *(int *)(&tmp[9]) = hash_code;
  write(unix_sock, tmp, 13);
  r = read(unix_sock, tmp, sizeof(tmp));
  if (r <= 0 || strcmp(tmp, "ok")) {
    exit(1);
  }

#endif
  return 0;
}

long long store_sutinfo(int func_code) {
  if (__fstate_shm_ptr) {
    *(__fstate_shm_ptr + 4 + func_code) = 1;
  }
  return 0;
}

unsigned int *extract_response_codes_ftp(unsigned char *buf,
                                         unsigned int buf_size) {
  char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int state_count = 0;
  char terminator[2] = {0x0D, 0x0A};
  char tmp[0x20];
  int r;
  mem = (char *)malloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)realloc(state_sequence,
                                           state_count * sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    if ((mem_count > 0) && (memcmp(&mem[mem_count - 1], terminator, 2) == 0)) {
      // Extract the response code which is the first 3 bytes
      char temp[4];
      memcpy(temp, mem, 4);
      temp[3] = 0x0;
      unsigned int message_code = (unsigned int)atoi(temp);
      if (message_code == 0)
        break;

      state_count++;
      create_new_bucket();
      //*(int *)__fstate_shm_ptr = message_code;
      memset(tmp, 0x0, 0x20);
      memcpy(tmp, "sync\0", 0x5);
      *(int *)(&tmp[5]) = ++bucket_index;
      *(int *)(&tmp[9]) = message_code;
      write(unix_sock, tmp, 13);
      r = read(unix_sock, tmp, sizeof(tmp));
      if (r <= 0 || strcmp(tmp, "ok")) {
        exit(1);
      }
      state_sequence = (unsigned int *)realloc(
          state_sequence, state_count * sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      mem_count = 0;
    } else {
      mem_count++;
      if (mem_count == mem_size) {
        // enlarge the mem buffer
        mem_size = mem_size * 2;
        mem = (char *)realloc(mem, mem_size);
      }
    }
  }
  if (mem)
    free(mem);
  return state_sequence;
}

unsigned int *extract_response_codes_rtsp(unsigned char *buf,
                                          unsigned int buf_size) {
  char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int state_count = 0;
  char terminator[2] = {0x0D, 0x0A};
  char rtsp[5] = {0x52, 0x54, 0x53, 0x50, 0x2f};
  char tmp[0x20];
  int r;
  mem = (char *)malloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)realloc(state_sequence,
                                           state_count * sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    // Check if the last two bytes are 0x0D0A
    if ((mem_count > 0) && (memcmp(&mem[mem_count - 1], terminator, 2) == 0)) {
      if ((mem_count >= 5) && (memcmp(mem, rtsp, 5) == 0)) {
        // Extract the response code which is the first 3 bytes
        char temp[4];
        memcpy(temp, &mem[9], 4);
        temp[3] = 0x0;
        unsigned int message_code = (unsigned int)atoi(temp);

        if (message_code == 0)
          break;

        state_count++;
        create_new_bucket();
        *(int *)__fstate_shm_ptr = message_code;
        memset(tmp, 0x0, 0x20);
        memcpy(tmp, "sync\0", 0x5);
        *(int *)(&tmp[5]) = ++bucket_index;
        *(int *)(&tmp[9]) = message_code;
        write(unix_sock, tmp, 13);
        r = read(unix_sock, tmp, sizeof(tmp));
        if (r <= 0 || strcmp(tmp, "ok")) {
          exit(1);
        }
        state_sequence = (unsigned int *)realloc(
            state_sequence, state_count * sizeof(unsigned int));
        state_sequence[state_count - 1] = message_code;
        mem_count = 0;
      } else {
        mem_count = 0;
      }
    } else {
      mem_count++;
      if (mem_count == mem_size) {
        // enlarge the mem buffer
        mem_size = mem_size * 2;
        mem = (char *)realloc(mem, mem_size);
      }
    }
  }
  if (mem)
    free(mem);
  return state_sequence;
}

static unsigned char dtls12_version[2] = {0xFE, 0xFD};

// (D)TLS known and custom constants

// the known 1-byte (D)TLS content types
#define CCS_CONTENT_TYPE 0x14
#define ALERT_CONTENT_TYPE 0x15
#define HS_CONTENT_TYPE 0x16
#define APPLICATION_CONTENT_TYPE 0x17
#define HEARTBEAT_CONTENT_TYPE 0x18

// custom content types
#define UNKNOWN_CONTENT_TYPE 0xFF // the content type is unrecognized

// custom handshake types (for handshake content)
#define UNKNOWN_MESSAGE_TYPE                                                   \
  0xFF // when the message type cannot be determined because the message is
       // likely encrypted
#define MALFORMED_MESSAGE_TYPE                                                 \
  0xFE // when message type cannot be determined because the message appears to
       // be malformed

unsigned int read_bytes_to_uint32(unsigned char *buf, unsigned int offset,
                                  int num_bytes) {
  unsigned int val = 0;
  for (int i = 0; i < num_bytes; i++) {
    val = (val << 8) + buf[i + offset];
  }
  return val;
}

unsigned int *extract_response_codes_dtls12(unsigned char *buf,
                                            unsigned int buf_size) {
  unsigned int byte_count = 0;
  unsigned int *state_sequence = NULL;
  unsigned int state_count = 0;
  unsigned int status_code = 0;
  char tmp[0x20];
  int r;

  state_count++;
  state_sequence = (unsigned int *)realloc(state_sequence,
                                           state_count * sizeof(unsigned int));
  state_sequence[state_count - 1] = 0; // initial status code is 0

  while (byte_count < buf_size) {
    // a DTLS 1.2 record has a 13 bytes header, followed by the contained
    // message
    if ((buf_size - byte_count > 13) &&
        (buf[byte_count] >= CCS_CONTENT_TYPE &&
         buf[byte_count] <= HEARTBEAT_CONTENT_TYPE) &&
        (memcmp(&buf[byte_count + 1], dtls12_version, 2) == 0)) {
      unsigned char content_type = buf[byte_count];
      unsigned char message_type;
      unsigned int record_length =
          read_bytes_to_uint32(buf, byte_count + 11, 2);

      // the record length exceeds buffer boundaries (not expected)
      if (buf_size - byte_count - 13 - record_length < 0) {
        message_type = MALFORMED_MESSAGE_TYPE;
      } else {
        switch (content_type) {
        case HS_CONTENT_TYPE:;
          unsigned char hs_msg_type = buf[byte_count + 13];
          // the minimum size of a correct DTLS 1.2 handshake message is 12
          // bytes comprising fragment header fields
          if (record_length >= 12) {
            unsigned int frag_length =
                read_bytes_to_uint32(buf, byte_count + 22, 3);
            // we can check if the handshake record is encrypted by subtracting
            // fragment length from record length which should yield 12 if the
            // fragment is not encrypted the likelyhood for an encrypted
            // fragment to satisfy this condition is very small
            if (record_length - frag_length == 12) {
              // not encrypted
              message_type = hs_msg_type;
            } else {
              // encrypted handshake message
              message_type = UNKNOWN_MESSAGE_TYPE;
            }
          } else {
            // malformed handshake message
            message_type = MALFORMED_MESSAGE_TYPE;
          }
          break;
        case CCS_CONTENT_TYPE:
          if (record_length == 1) {
            // unencrypted CCS
            unsigned char ccs_msg_type = buf[byte_count + 13];
            message_type = ccs_msg_type;
          } else {
            if (record_length > 1) {
              // encrypted CCS
              message_type = UNKNOWN_MESSAGE_TYPE;
            } else {
              // malformed CCS
              message_type = MALFORMED_MESSAGE_TYPE;
            }
          }
          break;
        case ALERT_CONTENT_TYPE:
          if (record_length == 2) {
            // unencrypted alert, the type is sufficient for determining which
            // alert occurred unsigned char level = buf[byte_count+13];
            unsigned char type = buf[byte_count + 14];
            message_type = type;
          } else {
            if (record_length > 2) {
              // encrypted alert
              message_type = UNKNOWN_MESSAGE_TYPE;
            } else {
              // malformed alert
              message_type = MALFORMED_MESSAGE_TYPE;
            }
          }
          break;
        case APPLICATION_CONTENT_TYPE:
          // for application messages we cannot determine whether they are
          // encrypted or not
          message_type = UNKNOWN_MESSAGE_TYPE;
          break;
        case HEARTBEAT_CONTENT_TYPE:
          // a heartbeat message is at least 3 bytes long (1 byte type, 2 bytes
          // payload length) unfortunately, telling an encrypted message from an
          // unencrypted message cannot be done reliably due to the variable
          // length of padding hence we just use unknown for either case
          if (record_length >= 3) {
            // unsigned char hb_msg_type = buf[byte_count+13];
            // u32 hb_length = read_bytes_to_uint32(buf, byte_count+14, 2);
            // unkown heartbeat message
            message_type = UNKNOWN_MESSAGE_TYPE;
          } else {
            // malformed heartbeat
            message_type = MALFORMED_MESSAGE_TYPE;
          }
          break;
        default:
          // unknown content and message type, should not be hit
          content_type = UNKNOWN_CONTENT_TYPE;
          message_type = UNKNOWN_MESSAGE_TYPE;
          break;
        }
      }

      status_code = (content_type << 8) + message_type;
      state_count++;
      create_new_bucket();
      //*(int *)__fstate_shm_ptr = status_code;
      memset(tmp, 0x0, 0x20);
      memcpy(tmp, "sync\0", 0x5);
      *(int *)(&tmp[5]) = ++bucket_index;
      *(int *)(&tmp[9]) = status_code;
      write(unix_sock, tmp, 13);
      r = read(unix_sock, tmp, sizeof(tmp));
      if (r <= 0 || strcmp(tmp, "ok")) {
        exit(1);
      }
      state_sequence = (unsigned int *)realloc(
          state_sequence, state_count * sizeof(unsigned int));
      state_sequence[state_count - 1] = status_code;
      byte_count += record_length;
    } else {
      // we shouldn't really be reaching this code
      byte_count++;
    }
  }

  return state_sequence;
}

unsigned int *extract_response_codes_ssh(unsigned char *buf,
                                         unsigned int buf_size) {
  char mem[7];
  unsigned int byte_count = 0;
  unsigned int *state_sequence = NULL;
  unsigned int state_count = 0;
  char tmp_buf[0x20];
  int r;

  // Initial state
  state_count++;
  state_sequence = (unsigned int *)realloc(state_sequence,
                                           state_count * sizeof(unsigned int));
  if (state_sequence == NULL)
    perror("Unable realloc a memory region to store state sequence");
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(mem, buf + byte_count, 6);
    byte_count += 6;

    /* If this is the identification message */
    if (strstr(mem, "SSH")) {
      // Read until \x0D\x0A
      char tmp = 0x00;
      while (tmp != 0x0A) {
        memcpy(&tmp, buf + byte_count, 1);
        byte_count += 1;
      }
      state_count++;
      state_sequence = (unsigned int *)realloc(
          state_sequence, state_count * sizeof(unsigned int));
      if (state_sequence == NULL)
        perror("Unable realloc a memory region to store state sequence");
      state_sequence[state_count - 1] = 256; // Identification
      create_new_bucket();
      //*(int *)__fstate_shm_ptr = 256;
      memset(tmp_buf, 0x0, 0x20);
      memcpy(tmp_buf, "sync\0", 0x5);
      *(int *)(&tmp_buf[5]) = ++bucket_index;
      *(int *)(&tmp_buf[9]) = 256;
      write(unix_sock, tmp_buf, 13);
      r = read(unix_sock, tmp_buf, sizeof(tmp_buf));
      if (r <= 0 || strcmp(tmp_buf, "ok")) {
        exit(1);
      }
    } else {
      // Extract the message type and skip the payload and the MAC
      unsigned int *size_buf = (unsigned int *)&mem[0];
      unsigned int message_size = (unsigned int)ntohl(*size_buf);

      // Break if the response does not adhere to the known format(s)
      // Normally, it only happens in the last response
      if (message_size - 2 > buf_size - byte_count)
        break;

      unsigned char message_code = (unsigned char)mem[5];
      state_count++;
      state_sequence = (unsigned int *)realloc(
          state_sequence, state_count * sizeof(unsigned int));
      if (state_sequence == NULL)
        perror("Unable realloc a memory region to store state sequence");
      state_sequence[state_count - 1] = message_code;
      create_new_bucket();
      memset(tmp_buf, 0x0, 0x20);
      memcpy(tmp_buf, "sync\0", 0x5);
      *(int *)(&tmp_buf[5]) = ++bucket_index;
      *(int *)(&tmp_buf[9]) = message_code;
      write(unix_sock, tmp_buf, 13);
      r = read(unix_sock, tmp_buf, sizeof(tmp_buf));
      if (r <= 0 || strcmp(tmp_buf, "ok")) {
        exit(1);
      }
      //*(int *)__fstate_shm_ptr = message_code;
      /* If this is a KEY exchange related message */
      if ((message_code >= 20) && (message_code <= 49)) {
        // Do nothing
      } else {
        message_size += 8;
      }
      byte_count += message_size - 2;
    }
  }
  return state_sequence;
}

unsigned int *extract_response_codes_tls(unsigned char *buf,
                                         unsigned int buf_size) {
  char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned char content_type, message_type;
  unsigned int *state_sequence = NULL;
  unsigned int state_count = 0;
  char tmp[0x20];
  int r;

  mem = (char *)malloc(mem_size);

  // Add initial state
  state_count++;
  state_sequence = (unsigned int *)realloc(state_sequence,
                                           state_count * sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;
  while (byte_count < buf_size) {

    memcpy(&mem[mem_count], buf + byte_count++, 1);

    // Check if the region buffer length is at least 6 bytes (5 bytes for record
    // header size) the 6th byte could be message type
    if (mem_count >= 6) {
      // 1st byte: content type
      // 2nd and 3rd byte: TLS version
      // Extract the message size stored in the 4th and 5th bytes
      content_type = mem[0];

      // Check if this is an application data record
      if (content_type != 0x17) {
        message_type = mem[5];
      } else {
        message_type = 0xFF;
      }

      unsigned short *size_buf = (unsigned short *)&mem[3];
      unsigned short message_size = (unsigned short)ntohs(*size_buf);

      // and skip the payload
      unsigned int bytes_to_skip = message_size - 1;
      unsigned int temp_count = 0;
      while ((byte_count < buf_size) && (temp_count < bytes_to_skip)) {
        byte_count++;
        temp_count++;
      }

      if (byte_count < buf_size) {
        byte_count--;
      }

      // add a new response code
      unsigned int message_code = (content_type << 8) + message_type;
      state_count++;
      create_new_bucket();
      //*(int *)__fstate_shm_ptr = message_code;
      memset(tmp, 0x0, 0x20);
      memcpy(tmp, "sync\0", 0x5);
      *(int *)(&tmp[5]) = ++bucket_index;
      *(int *)(&tmp[9]) = message_code;
      write(unix_sock, tmp, 13);
      r = read(unix_sock, tmp, sizeof(tmp));
      if (r <= 0 || strcmp(tmp, "ok")) {
        exit(1);
      }
      state_sequence = (unsigned int *)realloc(
          state_sequence, state_count * sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      mem_count = 0;
    } else {
      mem_count++;

      if (mem_count == mem_size) {
        // enlarge the mem buffer
        mem_size = mem_size * 2;
        mem = (char *)realloc(mem, mem_size);
      }
    }
  }
  if (mem)
    free(mem);

  return state_sequence;
}

int socket_checker(int socket_fd){
  int socket_type;
  socklen_t length = sizeof(socket_type);
  int sock_opt_ret = getsockopt(socket_fd, SOL_SOCKET, SO_TYPE, &socket_type, &length);
  if(sock_opt_ret != -1){
    //is socket
    return 0x1;
  }
  return 0x0;
}

long long update_sutstate_packet(char *send_buf, int send_size, int protocol, int need_socket_check) {
  if(need_socket_check){
      int ret = socket_checker(need_socket_check);
      if(!ret){
        return 0x0;
      }
  }
  switch (protocol) {
  case FTP:
    extract_response_codes_ftp((unsigned char *)send_buf, send_size);
    break;
  case RTSP:
    extract_response_codes_rtsp((unsigned char *)send_buf, send_size);
    break;
  case DTLS:
    extract_response_codes_dtls12((unsigned char *)send_buf, send_size);
    break;
  case SSH:
    extract_response_codes_ssh((unsigned char *)send_buf, send_size);
    break;
  case TLS:
    extract_response_codes_tls((unsigned char *)send_buf, send_size);
    break;
  default:
    break;
  }
  return 0;
}

int connect_monitor() {
  struct sockaddr_un unix_addr;
  int r, msg_len, func_count_fd, shm_id;
  char buf[MAX_BUF], *shm_env, *func_count_env;

  func_count_env = getenv("DEFINITION_CHECKER_LIST");
  if (func_count_env) {
    memset(buf, 0x0, sizeof(buf));
    sprintf(buf, "%s/bb_count.txt", func_count_env);
    func_count_fd = open(buf, O_RDONLY);
    if (func_count_fd <= 0) {
      perror("[!]open func count failed");
      exit(1);
    }
    memset(buf, 0x0, sizeof(buf));
    r = read(func_count_fd, buf, sizeof(buf));
    if (r <= 0) {
      perror("[!]read failed");
      exit(1);
    }
    bucket_size = atoi(buf) + 1;
  }

  unix_sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (unix_sock <= 0) {
    perror("[!]socket open failed");
    exit(1);
  }

  memset(&unix_addr, 0x0, sizeof(unix_addr));
  unix_addr.sun_family = AF_UNIX;
  strncpy(unix_addr.sun_path, SOCK_PATH, sizeof(unix_addr.sun_path) - 1);

  r = connect(unix_sock, (struct sockaddr *)&unix_addr, sizeof(unix_addr));
  if (r < 0) {
    perror("[!]connect_monitor failed");
    exit(1);
  }
  memset(buf, 0x0, MAX_BUF);
  memcpy(buf, "init", 0x4);
  msg_len = 5;
#ifdef AFLNET_CLIENT
  *(int *)(&buf[msg_len]) = 0xdeadbeef;
  msg_len += 4;
  *(int *)(&buf[msg_len]) = bucket_size;
  msg_len += 4;
#endif
#ifdef STATEAFL_CLIENT
  shm_env = getenv("SHM_STATE_ENV_VAR");
  if (shm_env) {
    shm_id = atoi(shm_env);
    *(int *)(&buf[msg_len]) = shm_id;
    msg_len += 4;
  } else {
    *(int *)(&buf[msg_len]) = 0x0;
    msg_len += 4;
  }
  *(int *)(&buf[msg_len]) = bucket_size;
  msg_len += 4;
#endif
#ifdef NSFUZZ_CLIENT
  shm_env = getenv("__AFL_STATE_SHM_ID");
  if (shm_env) {
    shm_id = atoi(shm_env);
    *(int *)(&buf[msg_len]) = shm_id;
    msg_len += 4;
  }
  *(int *)(&buf[msg_len]) = bucket_size;
  msg_len += 4;

#endif

  write(unix_sock, buf, msg_len);
  memset(buf, 0x0, sizeof(buf));
  r = read(unix_sock, buf, sizeof(buf));
  if (r == 4) {
    __fstate_shm_id = *(int *)buf;
    __fstate_shm_ptr = __fstate_shm_base =
        (char *)shmat(__fstate_shm_id, NULL, NULL);
    if (__fstate_shm_ptr == NULL) {
      perror("[!]shmat failed");
      exit(1);
    }
  }

  return 0;
}
