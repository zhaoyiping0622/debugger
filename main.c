#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <linux/version.h>
#include <linux/limits.h>
#include <sys/ptrace.h>
#include <elf.h>
#include <errno.h>
#include <sys/wait.h>

/*
 * On i386, pt_regs and user_regs_struct are the same,
 * but on 64 bit x86, user_regs_struct has six more fields:
 * fs_base, gs_base, ds, es, fs, gs.
 * PTRACE_GETREGS fills them too, so struct pt_regs would overflow.
 */
struct i386_user_regs_struct {
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
  uint32_t esi;
  uint32_t edi;
  uint32_t ebp;
  uint32_t eax;
  uint32_t xds;
  uint32_t xes;
  uint32_t xfs;
  uint32_t xgs;
  uint32_t orig_eax;
  uint32_t eip;
  uint32_t xcs;
  uint32_t eflags;
  uint32_t esp;
  uint32_t xss;
};

static union {
  struct user_regs_struct x86_64_r;
  struct i386_user_regs_struct i386_r;
} x86_regs_union;

#define x86_64_regs x86_regs_union.x86_64_r

#define i386_regs x86_regs_union.i386_r

static struct iovec x86_io = {.iov_base = &x86_regs_union};

long get_regs_error;

void get_regs(pid_t pid) {

  if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)) {
    /*x86_io.iov_base = &x86_regs_union; - already is */
    x86_io.iov_len = sizeof(x86_regs_union);
    get_regs_error = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &x86_io);
  } else {
    /* Use old method, with heuristical detection of 32-bitness */
    x86_io.iov_len = sizeof(x86_64_regs);
    get_regs_error = ptrace(PTRACE_GETREGS, pid, NULL, &x86_64_regs);
    if (!get_regs_error && x86_64_regs.cs == 0x23) {
      x86_io.iov_len = sizeof(i386_regs);
      /*
       * The order is important: i386_regs and x86_64_regs
       * are overlaid in memory!
       */
      i386_regs.ebx = x86_64_regs.rbx;
      i386_regs.ecx = x86_64_regs.rcx;
      i386_regs.edx = x86_64_regs.rdx;
      i386_regs.esi = x86_64_regs.rsi;
      i386_regs.edi = x86_64_regs.rdi;
      i386_regs.ebp = x86_64_regs.rbp;
      i386_regs.eax = x86_64_regs.rax;
      /*i386_regs.xds = x86_64_regs.ds; unused by strace */
      /*i386_regs.xes = x86_64_regs.es; ditto... */
      /*i386_regs.xfs = x86_64_regs.fs;*/
      /*i386_regs.xgs = x86_64_regs.gs;*/
      i386_regs.orig_eax = x86_64_regs.orig_rax;
      i386_regs.eip = x86_64_regs.rip;
      /*i386_regs.xcs = x86_64_regs.cs;*/
      /*i386_regs.eflags = x86_64_regs.eflags;*/
      i386_regs.esp = x86_64_regs.rsp;
      /*i386_regs.xss = x86_64_regs.ss;*/
    }
  }
  if (get_regs_error < 0) {
    printf("get_regs failed, errno=%s", strerror(errno));
  }
}

long getBaseAddr(pid_t pid) {
  char location[PATH_MAX];
  char programName[PATH_MAX];
  sprintf(location, "/proc/%d/cmdline", pid);
  FILE *f = fopen(location, "r");
  if (f == NULL) {
    fprintf(stderr, "file %s not exist", location);
    exit(1);
  }
  fscanf(f, "%s", programName);
  fclose(f);
  char *s = realpath(programName, NULL);
  memcpy(programName, s, strlen(s));
  free(s);
  sprintf(location, "/proc/%d/maps", pid);
  f = fopen(location, "r");
  if (f == NULL) {
    fprintf(stderr, "file %s not exist", location);
    exit(1);
  }
  long tmpBegin, tmpEnd;
  char perms[5];
  char pathName[PATH_MAX];
  int cnt = 0;
  long begin, end;
  while (!feof(f)) {
    char s[4096];
    fgets(s, 4096, f);
    sscanf(s, "%lx-%lx %s %*s %*s %*s %s", &tmpBegin, &tmpEnd, perms, pathName);
    if (strcmp(pathName, programName) == 0 && (strcmp(perms, "r-xp") == 0 || strcmp(perms, "rwxp") == 0)) {
      begin = tmpBegin;
      end = tmpEnd;
      cnt++;
    }
  }
  if (cnt != 1) {
    fprintf(stderr, "error in coding, please contact to the writer.");
    exit(1);
  }
  fclose(f);
  return begin;
}

long breakpointLocation[1024];
unsigned long breakpointValue[1024];

void setBreakpoint(pid_t pid, long location) {
  int i;
  for (i = 0; breakpointLocation[i] && i < 1024; i++)
    if (location == breakpointLocation[i]) {
      ptrace(PTRACE_POKETEXT, pid, (void *)location, (breakpointValue[i] & ~0xff) | 0xcc);
      return;
    }
  if (i == 1024) {
    fprintf(stderr, "you should only set 1024 breakpoints");
    exit(1);
  }
  unsigned long originData = ptrace(PTRACE_PEEKTEXT, pid, (void *)location, NULL);
  breakpointValue[i] = originData;
  ptrace(PTRACE_POKETEXT, pid, (void *)location, (originData & ~0xff) | 0xcc);
  breakpointLocation[i] = location;
}

long restoreBreakpoint(pid_t pid, char all) {
  get_regs(pid);
  for (int i = 0; breakpointLocation[i]; i++) {
    if (breakpointLocation[i] + 1 == x86_64_regs.rip || all) {
      ptrace(PTRACE_POKETEXT, pid, (void *)(breakpointLocation[i]), breakpointValue[i]);
      if (!all) {
        x86_64_regs.rip--;// breakpoint
        if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)) {
          ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &x86_io);
        } else {
          ptrace(PTRACE_SETREGS, pid, NULL, &x86_64_regs);
        }
        return breakpointLocation[i];
      }
    }
  }
//  fprintf(stderr, "error:rip=0x%lx\n", x86_64_regs.rip);
//  exit(1);
  return -1;
}

void oneStep(pid_t pid) {
  int wait_val;
  long bp = restoreBreakpoint(pid, 0);
  ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
  wait(&wait_val);
  if (bp != -1)
    setBreakpoint(pid, bp);
}

void printrip(pid_t pid) {
  get_regs(pid);
  fprintf(stderr, "0x%llx\n", x86_64_regs.rip);
}

void printData(pid_t pid, long location, long size) {
  for (int i = 0; i * 8 < size; i++) {
    unsigned long data = ptrace(PTRACE_PEEKTEXT, pid, (void *)(location + i * 8), NULL);
    printf("%016lx\n", data);
  }
}

void debugger(pid_t pid) {
  long baseAddr = getBaseAddr(pid);
  int wait_val;
  do {
    char command[1024];
    while (1) {
      printf("> ");
      char b = 0;
      fgets(command, 1024, stdin);
      switch (command[0]) {
        case 'b': {
          int location;
          sscanf(command, "%*s %x", &location);
          setBreakpoint(pid, location + baseAddr);
          break;
        }
        case 'c': {
          // continue
          b = 1;
          break;
        }
        case 'd': {
          restoreBreakpoint(pid, 1);
          get_regs(pid);
          x86_64_regs.rip--;// breakpoint
          if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)) {
            ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &x86_io);
          } else {
            ptrace(PTRACE_SETREGS, pid, NULL, &x86_64_regs);
          }
          ptrace(PTRACE_DETACH, pid, NULL, NULL);
          wait(&wait_val);
          return;
        }
        case 'h':{
          printf("usage:(all integer should input in hexadecimal format)\n");
          printf("b *breakpoint*       setbreakpoint\n");
          printf("c                    continue\n");
          printf("d                    detach\n");
          printf("n                    next instruction\n");
          printf("q                    quit\n");
          printf("p *location* *size*  print the value in location\n");
          printf(".                    print RIP\n");
        }
        case 'n': {
          oneStep(pid);
          break;
        }
        case 'q': {
          return;
        }
        case 'p': {
          long location;
          long size;
          sscanf(command, "%*s %lx %lx", &location, &size);
          printData(pid, location + baseAddr, size);
          break;
        }
        case '.': {
          printrip(pid);
          break;
        }
      }
      if (b)break;
    }
    oneStep(pid);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    wait(&wait_val);
  } while (WIFSTOPPED(wait_val));
}

pid_t RunProgram(char *program) {
  pid_t pid;
  int wait_val;
  switch (pid = fork()) {
    case -1:fprintf(stderr, "error in fork");
      exit(1);
    case 0:// son
      ptrace(PTRACE_TRACEME, 0, NULL, NULL);
      execl(program, program, NULL);
    default:wait(&wait_val);
      return pid;
  }
}

pid_t AttachProgram(pid_t pid) {
  int wait_val;
  ptrace(PTRACE_ATTACH, pid, NULL, NULL);
  if (errno) {
    fprintf(stderr, "errno: %d %s\n", errno, strerror(errno));
    exit(1);
  }
  wait(&wait_val);
  return pid;
}

int main(int argc, char *argv[]) {
  if (argc == 1 || argc > 1 && strcmp("--help", argv[1]) == 0) {
    fprintf(stderr, "usage: %s [--help] [PROGRAM or --attach PID]", argv[0]);
    exit(0);
  }
  pid_t program_pid;
  if (strcmp("--attach", argv[1]) == 0) {
    if (argc == 2)
      fprintf(stderr, "usage: %s [--help] [PROGRAM or --attach PID]", argv[0]);
    program_pid = AttachProgram(atoi(argv[2]));
  } else {
    program_pid = RunProgram(argv[1]);
  }
  debugger(program_pid);
  return 0;
}
