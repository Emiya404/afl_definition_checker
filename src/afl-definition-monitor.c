#define _GNU_COURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ipc.h>
#include <sys/select.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
/*
 * NOTE:
 * 1. Why to implement a monitor:
 * Final state code cannot be calculated when state changes.
 * State code may be calculated after a fuzz execution (STATEAFL)
 * State code may be calculated in afl process (NSFUZZ AFLNETLEGION)
 * 2. monitor workflow
 * When SUT wakes up, SUT will send packets to Monitor to notify monitor to
 * clear shm.
 * When state changes, SUT will send packets to Monotor to notify
 * monitor to update state bucket.
 * When SUT destructor runs, SUT will send
 * packets to monitor to notify monitor to save files.
 */

#define SOCK_PATH "/tmp/afl-definition-monitor"
#define MONITOR_MAP_SIZE_POW 24
#define MONITOR_MAP_SIZE (1 << MONITOR_MAP_SIZE_POW)
#define MAX_SUTS 5
#define MAX_EVENTS 10
#define MAX_BUF 2048
#define MAX_NAME 32
#define HASH_CONST 0xa5b35705
#define ROL64(_x, _r)                                                          \
  ((((unsigned long long)(_x)) << (_r)) |                                      \
   (((unsigned long long)(_x)) >> (64 - (_r))))

static inline int hash32(const void *key, unsigned int len, unsigned int seed) {

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

int unix_fd;
int shm_id;
unsigned char *shm_ptr, *base_ptr;
struct sockaddr_un unix_addr;
int extra_shm_id;
char *extra_shm_ptr;
int bucket_size, bucket_index;
int file_index;

void destroy_sock() {
  if (unix_fd) {
    // printf("[*]destroy_sock %d \n", unix_fd);
    close(unix_fd);
    unlink(SOCK_PATH);
  }
  return;
}

int init_unix_sock() {
  int r;

  unlink(SOCK_PATH);

  int unix_sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (unix_sock <= 0) {
    perror("[!]open socket fd failed");
    exit(1);
  }

  memset(&unix_addr, 0x0, sizeof(unix_addr));
  unix_addr.sun_family = AF_UNIX;
  memcpy(unix_addr.sun_path, SOCK_PATH, sizeof(unix_addr.sun_path) - 1);

  r = bind(unix_sock, (struct sockaddr *)&unix_addr, sizeof(unix_addr));
  if (r < 0) {
    perror("[!]bind socket addr failed");
    exit(1);
  }
  atexit(destroy_sock);
  unix_fd = unix_sock;
  // printf("[*]afl-definition-monitor has bound unix_sock %s\n", SOCK_PATH);
  return unix_sock;
}

void destroy_shm() {
  if (shm_id && shm_ptr) {
    // printf("[*]destroy_shm %d\n", shm_id);
    shmctl(shm_id, IPC_RMID, NULL);
  }
}

int init_state_shm() {
  shm_id = shmget(IPC_PRIVATE, MONITOR_MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);
  if (shm_id < 0) {
    perror("[!]shmget failed");
    exit(1);
  }
  // printf("[*]init_state_shm shm_id %d\n", shm_id);
  shm_ptr = (unsigned char *)shmat(shm_id, 0, 0);
  if (shm_ptr == NULL) {
    perror("[!]shmat failed");
    exit(1);
  }
  // printf("[*]init_state_shm shm_ptr %p\n", shm_ptr);
  base_ptr = shm_ptr;
  atexit(destroy_shm);
  return shm_id;
}

void signal_handler(int signo) {
  // destroy_sock();
  // destroy_shm();
  exit(1);
  return;
}

int init_signal() {
  struct sigaction sa;
  int r;

  memset(&sa, 0x0, sizeof(sa));
  sa.sa_handler = signal_handler;
  sa.sa_flags |= SA_RESTART;
  sigemptyset(&sa.sa_mask);
  r = sigaction(SIGINT, &sa, NULL);
  if (r < 0) {
    perror("[!]sigaction failed");
    exit(1);
  }
  // printf("[*]init_signal\n");
  signal(SIGPIPE, SIG_IGN);
  return 0;
}

int do_sut_state_machine(int epoll_fd, int sut_sock_fd, unsigned int evs) {
  /*
   * NOTE:
   * SUT will go through following steps during its life span:
   * 1. initialize: fksrv fork new SUT, the SUT notify this server
   * and get shm_id to access shm.
   * 2. running: SUT fill the shm referred by shm_ptr and send sync
   * info when state changes. After sending sync info, SUT stuck in
   * reading from unix sock, waiting for server to calculate state.
   * 3. destructor: SUT do finalize. Server save instrumentation data
   * and clear the shm.
   */
  char buf[MAX_BUF], tmp[MAX_NAME];
  int r;
  int save_fd, save_len;
  int hash_value;
  int state_code;


  if(evs & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)){
    r = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, sut_sock_fd, NULL);
    printf("there 1 %d\n", r);
    if(r < 0){
      perror("[!]delete fucking shit\n");
    }
    r = close(sut_sock_fd);
    if(r < 0){
      perror("[!]delete fucking shit 2\n");
    }
    
    save_len = (bucket_index + 1) * (bucket_size + 4);
    if (save_len < 0) {
      // printf("[!]error bucket size\n");
      return -1;
    }
    memset(tmp, 0x0, sizeof(tmp));
    sprintf(tmp, "./result/fstate_%d", file_index++);
    save_fd = open(tmp, O_RDWR | O_CREAT, 0666);
    if (save_fd < 0) {
      perror("[!]open save failed");
      exit(1);
    }
    r = write(save_fd, shm_ptr, save_len);
    close(save_fd);
    printf("saved %d %s\n", save_fd, tmp);
    memset(shm_ptr, 0x0, save_len);
    if (r != save_len) {
      perror("[!]save err");
      exit(1);
    }
    printf("[*]SUT life end, bucket index = %d\n", bucket_index);
    bucket_index = 0;

    return -1;
  }

  memset(buf, 0x0, sizeof(buf));
  r = read(sut_sock_fd, buf, sizeof(buf) - 1);
  if (r < 0) {
    /* WARN:
     * Program runs here only when SUT exit accidently.
     * Write this for stability.
     */
    printf("[$]read result %d\n", r);
    if (errno == EAGAIN || errno == EWOULDBLOCK){
      printf("there 2\n");
      return 0;
    }
    //printf("fuck1\n");
    //epoll_ctl(epoll_fd, EPOLL_CTL_DEL, sut_sock_fd, NULL);
    //close(sut_sock_fd);
    bucket_index = 0;

    return -1;
  }
  if (r == 0) {
    printf("[*]SUT life end, bucket index = %d\n", bucket_index);
    return -1;
  }
  /*
   * NOTE:
   * monitor socket format
   * | init\0 | extra_shm_id | bucket_size |
   * | sync\0 | bucket_index | message code |
   * | fini\0 |
   */
  if (!strcmp(buf, "init")) {

    write(sut_sock_fd, &shm_id, sizeof(shm_id));
    extra_shm_id = *(int *)(&buf[5]);
    if (extra_shm_id) {
      extra_shm_ptr = shmat(extra_shm_id, 0, 0);
      if (extra_shm_ptr == NULL) {
        return -1;
      }
    }
    bucket_size = *(int *)(&buf[9]);
    //printf("[*] recvd init msg: shm_id %d, bucket_size %d\n", extra_shm_id,
    //bucket_size);
  } else if (!strcmp(buf, "sync")) {

    bucket_index = *(int *)(&buf[5]);
    state_code = *(int *)(&buf[9]);
    *(int *)(shm_ptr + (bucket_size + 4) * bucket_index) = state_code;
    //printf("[*] recvd sync msg: bucket_index %d, state_code %d\n",
    //bucket_index, state_code);
    write(sut_sock_fd, "ok\0", 0x3);

  } else {
    printf("there 3\n");
    return -1;
  }
  return 0;
}

int main() {
  int r;
  int epoll_fd;
  struct epoll_event ev, events[MAX_EVENTS];
  int connected_fd;

  // printf("[*]enter afl-definition-monitor\n");
  init_unix_sock();
  init_state_shm();
  init_signal();

  r = listen(unix_fd, MAX_SUTS);
  if (r < 0) {
    perror("[!]listen failed");
    exit(1);
  }

  r = epoll_create(MAX_SUTS);
  if (r < 0) {
    perror("[!]epoll_create failed");
    exit(1);
  }
  // printf("[*]created new epoll_fd %d\n", epoll_fd);
  epoll_fd = r;
  ev.events = EPOLLIN;
  ev.data.fd = unix_fd;
  r = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, unix_fd, &ev);
  if (r < 0) {
    perror("[!]epoll_ctl failed");
    exit(1);
  }

  for (;;) {
    r = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
    if (r < 0) {
      perror("[!]epoll_wait failed");
      exit(1);
    }
    for (int i = 0; i < r; i++) {
      unsigned int evs = events[i].events;
      if (events[i].data.fd == unix_fd) {
        // printf("[*]new client has been connected\n");
        connected_fd = accept(unix_fd, NULL, NULL);
        if (connected_fd < 0) {
          perror("[!]accept failed");
          exit(1);
        }
        r = fcntl(connected_fd, F_GETFL, 0);
        if (r == -1 || fcntl(connected_fd, F_SETFL, r | O_NONBLOCK) < 0) {
          perror("[!]fcntl failed");
          exit(1);
        }
        ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
        ev.data.fd = connected_fd;
        r = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, connected_fd, &ev);
        printf("[*]new fd %d has been accepted\n", connected_fd);
        if (r < 0) {
          perror("[!]epoll_ctl failed");
          exit(1);
        }
      } else {
        int r = do_sut_state_machine(epoll_fd, events[i].data.fd, evs);
      	if (r < 0) {
		printf("client end \n");
		//epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
		//close(events[i].data.fd);
	}
      }
    }
  }
}
