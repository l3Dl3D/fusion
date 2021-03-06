#include "../common/common.c"    

#include <task.h>

#define STACK (4096 * 8)

unsigned int hash(unsigned char *str, int length, unsigned int mask)
{
  unsigned int h = 0xfee13117;
  int i;

  for(h = 0xfee13117, i = 0; i < length; i++) {
      h ^= str[i];
      h += (h << 11);
      h ^= (h >> 7);
      h -= str[i];
  }
  h += (h << 3);
  h ^= (h >> 10);
  h += (h << 15);
  h -= (h >> 17);

  return (h & mask);
}

void fdprintf(int fd, char *fmt, ...)
{
  va_list ap;
  char *msg = NULL;

  va_start(ap, fmt);
  vasprintf(&msg, fmt, ap);
  va_end(ap);

  if(msg) {
      fdwrite(fd, msg, strlen(msg));    
      free(msg);
  }
}

struct registrations {
  short int flags;
  in_addr_t ipv4;
} __attribute__((packed));

#define REGDB (128)
struct registrations registrations[REGDB];

static void addreg(void *arg)
{
  char *name, *sflags, *ipv4, *p;
  int h, flags;
  char *line = (char *)(arg);
  
  name = line;
  p = strchr(line, ' ');
  if(! p) goto bail;
  *p++ = 0;
  sflags = p;
  p = strchr(p, ' ');
  if(! p) goto bail;
  *p++ = 0;
  ipv4 = p;

  flags = atoi(sflags);
  if(flags & ~0xe0) goto bail;

  h = hash(name, strlen(name), REGDB-1);
  registrations[h].flags = flags;
  registrations[h].ipv4 = inet_addr(ipv4);

  printf("registration added successfully\n");

bail:
  free(line);
}

static void senddb(void *arg)
{
  unsigned char buffer[512], *p;
  char *host, *l;
  char *line = (char *)(arg);
  int port;
  int fd;
  int i;
  int sz;

  p = buffer;
  sz = sizeof(buffer);
  host = line;
  l = strchr(line, ' ');
  if(! l) goto bail;
  *l++ = 0;
  port = atoi(l);
  if(port == 0) goto bail;

  printf("sending db\n");

  if((fd = netdial(UDP, host, port)) < 0) goto bail;

  for(sz = 0, p = buffer, i = 0; i < REGDB; i++) {
      if(registrations[i].flags | registrations[i].ipv4) {
          memcpy(p, &registrations[i], sizeof(struct registrations));
          p += sizeof(struct registrations);
          sz += sizeof(struct registrations);
      }
  }
bail:
  fdwrite(fd, buffer, sz);
  close(fd);
  free(line);
}

int get_and_hash(int maxsz, char *string, char separator)
{
  char name[32];
  int i;
  
  if(maxsz > 32) return 0;

  for(i = 0; i < maxsz, string[i]; i++) {
      if(string[i] == separator) break;
      name[i] = string[i];
  }

  return hash(name, strlen(name), 0x7f);
}


struct isuparg {
  int fd;
  char *string;
};


static void checkname(void *arg)
{
  struct isuparg *isa = (struct isuparg *)(arg);
  int h;

  h = get_and_hash(32, isa->string, '@');
  
  fdprintf(isa->fd, "%s is %sindexed already\n", isa->string, registrations[h].ipv4 ? "" : "not ");

}

static void isup(void *arg)
{
  unsigned char buffer[512], *p;
  char *host, *l;
  struct isuparg *isa = (struct isuparg *)(arg);
  int port;
  int fd;
  int i;
  int sz;

  // skip over first arg, get port
  l = strchr(isa->string, ' ');
  if(! l) return;
  *l++ = 0;

  port = atoi(l);
  host = malloc(64);

  for(i = 0; i < 128; i++) {
      p = (unsigned char *)(& registrations[i]);
      if(! registrations[i].ipv4) continue;

      sprintf(host, "%d.%d.%d.%d",
          (registrations[i].ipv4 >> 0) & 0xff,
          (registrations[i].ipv4 >> 8) & 0xff,
          (registrations[i].ipv4 >> 16) & 0xff,
          (registrations[i].ipv4 >> 24) & 0xff);

      if((fd = netdial(UDP, host, port)) < 0) {
          continue;
      }

      buffer[0] = 0xc0;
      memcpy(buffer + 1, p, sizeof(struct registrations));
      buffer[5] = buffer[6] = buffer[7] = 0;

      fdwrite(fd, buffer, 8);

      close(fd);
  }

  free(host);
}

static void childtask(void *arg)
{
  int cfd = (int)(arg);
  char buffer[512], *n;
  int r;
  

  n = "** welcome to level05 **\n";

  if(fdwrite(cfd, n, strlen(n)) < 0) goto bail;

  while(1) {
      if((r = fdread(cfd, buffer, 512)) <= 0) goto bail;

      n = strchr(buffer, '\r');
      if(n) *n = 0;
      n = strchr(buffer, '\n');
      if(n) *n = 0;

      if(strncmp(buffer, "addreg ", 7) == 0) {
          taskcreate(addreg, strdup(buffer + 7), STACK);
          continue;
      }

      if(strncmp(buffer, "senddb ", 7) == 0) {
          taskcreate(senddb, strdup(buffer + 7), STACK);
          continue;
      }

      if(strncmp(buffer, "checkname ", 10) == 0) {
          struct isuparg *isa = calloc(sizeof(struct isuparg), 1);

          isa->fd = cfd;
          isa->string = strdup(buffer + 10);

          taskcreate(checkname, isa, STACK);
          continue;
      }
  
      if(strncmp(buffer, "quit", 4) == 0) {
          break;
      }

      if(strncmp(buffer, "isup ", 5) == 0) {
          struct isuparg *isa = calloc(sizeof(struct isuparg), 1);
          isa->fd = cfd;
          isa->string = strdup(buffer + 5);
          taskcreate(isup, isa, STACK);
      }
  }

bail:
  close(cfd); 
}

void taskmain(int argc, char **argv)
{
  int fd, cfd;
  char remote[16];
  int rport;    

  signal(SIGPIPE, SIG_IGN);
  background_process(NAME, UID, GID); 

  if((fd = netannounce(TCP, 0, PORT)) < 0) {
      fprintf(stderr, "failure on port %d: %s\n", PORT, strerror(errno));
      taskexitall(1);
  }

  fdnoblock(fd);

  while((cfd = netaccept(fd, remote, &rport)) >= 0) {
      fprintf(stderr, "accepted connection from %s:%d\n", remote, rport);
      taskcreate(childtask, (void *)(cfd), STACK);
  }

  

}

