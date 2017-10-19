/*
 * ProFTPD: mod_counter -- a module for using counters to enforce per-file usage
 * Copyright (c) 2004-2017 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * This is mod_counter, contrib software for proftpd 1.2.10rc1 and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "conf.h"
#include "privs.h"
#include "mod_ctrls.h"

#include <sys/ipc.h>
#include <sys/sem.h>

#define MOD_COUNTER_VERSION	"mod_counter/0.6"

#if PROFTPD_VERSION_NUMBER < 0x0001030201
# error "ProFTPD 1.3.2rc1 or later required"
#endif

#define COUNTER_PROJ_ID			247
#define COUNTER_NSEMS			3
#define COUNTER_READER_SEMNO		0
#define COUNTER_WRITER_SEMNO		1
#define COUNTER_NPROCS_SEMNO		2

#define COUNTER_DEFAULT_MAX_READERS	0
#define COUNTER_DEFAULT_MAX_WRITERS	1

module counter_module;

struct counter_fh {
  struct counter_fh *next, *prev;
  const char *area;
  size_t arealen;
  int isglob;
  pr_fh_t *fh;
};

static pool *counter_pool = NULL;

static xaset_t *counter_fhs = NULL;
static const char *counter_curr_path = NULL;
static int counter_curr_semid = -1;
static int counter_engine = FALSE;
static int counter_max_readers = COUNTER_DEFAULT_MAX_READERS;
static int counter_max_writers = COUNTER_DEFAULT_MAX_WRITERS;
static int counter_logfd = -1;

static int counter_pending = 0;
#define COUNTER_HAVE_READER	0x01
#define COUNTER_HAVE_WRITER	0x02

#if (defined(__GNU_LIBRARY__) && !defined(_SEM_SEMUN_UNDEFINED)) || defined(DARWIN9)
#else
union semun {
  int val;
  struct semid_ds *buf;
  unsigned short int *array;
  struct seminfo *__buf;
};
#endif

#ifndef HAVE_FLOCK
# define LOCK_SH        1
# define LOCK_EX        2
# define LOCK_UN        8
# define LOCK_NB        4
#endif /* HAVE_FLOCK */

static int counter_file_lock(pr_fh_t *, int);
static array_header *counter_file_read(pr_fh_t *);
static int counter_file_write(pr_fh_t *, array_header *);
static int counter_set_procs(int);
static int counter_set_readers(int);
static int counter_set_writers(int);

/* Support routines
 */

static int counter_add_reader(int semid) {
  struct sembuf s[2];

  s[0].sem_num = COUNTER_READER_SEMNO;
  s[0].sem_op = -1;
  s[0].sem_flg = IPC_NOWAIT|SEM_UNDO;

  s[1].sem_num = COUNTER_NPROCS_SEMNO;
  s[1].sem_op = -1;
  s[1].sem_flg = IPC_NOWAIT|SEM_UNDO;

  return semop(semid, s, 2);
}

static int counter_add_writer(int semid) {
  struct sembuf s[2];

  s[0].sem_num = COUNTER_WRITER_SEMNO;
  s[0].sem_op = -1;
  s[0].sem_flg = IPC_NOWAIT|SEM_UNDO;

  s[1].sem_num = COUNTER_NPROCS_SEMNO;
  s[1].sem_op = -1;
  s[1].sem_flg = IPC_NOWAIT|SEM_UNDO;

  return semop(semid, s, 2);
}

static int counter_file_add_id(pr_fh_t *fh, int semid) {
  int res;
  array_header *ids;

  if (counter_file_lock(fh, LOCK_EX) < 0)
    return -1;

  ids = counter_file_read(fh);
  if (!ids) {
    int xerrno = errno;
    counter_file_lock(fh, LOCK_UN);

    errno = xerrno;
    return -1;
  }

  *((int *) push_array(ids)) = semid;

  res = counter_file_write(fh, ids);

  counter_file_lock(fh, LOCK_UN);
  return res;
}

static int counter_file_lock(pr_fh_t *fh, int op) {
  static int counter_have_lock = FALSE;

#ifdef HAVE_FLOCK
  int res;
#else
  int flag;
  struct flock lock;
#endif /* HAVE_FLOCK */

  if (counter_have_lock &&
      ((op & LOCK_SH) || (op & LOCK_EX)))
    return 0;

  if (!counter_have_lock &&
      (op & LOCK_UN))
    return 0;

#ifdef HAVE_FLOCK
  res = flock(fh->fh_fd, op);
  if (res == 0) {
    if ((op & LOCK_SH) ||
        (op & LOCK_EX)) {
      counter_have_lock = TRUE;

    } else if (op & LOCK_UN) {
      counter_have_lock = FALSE;
    }
  }

  return res;
#else
  flag = F_SETLKW;

  lock.l_whence = 0;
  lock.l_start = lock.l_len = 0;

  if (op & LOCK_SH) {
    lock.l_type = F_RDLCK;

  } else if (op & LOCK_EX) {
    lock.l_type = F_WRLCK;

  } else if (op & LOCK_UN) {
    lock.l_type= F_UNLCK;

  } else {
    errno = EINVAL;
    return -1;
  }

  if (op & LOCK_NB)
    flag = F_SETLK;

  while (fcntl(fh->fh_fd, flag, &lock) < 0) {
    if (errno == EINTR) {
      pr_signals_handle();
      continue;
    }

    return -1;
  }

  if ((op & LOCK_SH) ||
      (op & LOCK_EX)) {
    counter_have_lock = TRUE;

  } else if (op & LOCK_UN) {
    counter_have_lock = FALSE;
  }

  return 0;
#endif /* HAVE_FLOCK */
}

static array_header *counter_file_read(pr_fh_t *fh) {
  char buf[PR_TUNABLE_BUFFER_SIZE];
  array_header *ids = make_array(counter_pool, 0, sizeof(int));

  /* Read the list of IDs in the CounterFile into an array. */

  if (counter_file_lock(fh, LOCK_SH) < 0) {
    (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
      "error read-locking CounterFile '%s': %s", fh->fh_path, strerror(errno));
  }

  if (pr_fsio_lseek(fh, 0, SEEK_SET) < 0) {
    int xerrno = errno;

    counter_file_lock(fh, LOCK_UN);
    errno = xerrno;

    return NULL;
  }

  memset(buf, '\0', sizeof(buf));
  while (pr_fsio_gets(buf, sizeof(buf), fh) != NULL) {
    int id;

    pr_signals_handle();

    id = atoi(buf);
    if (id < 0)
      continue;

    *((int *) push_array(ids)) = id;
  }

  if (counter_file_lock(fh, LOCK_UN) < 0) {
    (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
      "error unlocking CounterFile '%s': %s", fh->fh_path, strerror(errno));
  }

  return ids;
}

static int counter_file_remove_id(pr_fh_t *fh, int semid) {
  register unsigned int i;
  int res;
  array_header *ids;
  int *semids;

  if (counter_file_lock(fh, LOCK_EX) < 0)
    return -1;

  ids = counter_file_read(fh);
  if (!ids) {
    int xerrno = errno;

    counter_file_lock(fh, LOCK_UN);

    errno = xerrno;
    return -1;
  }

  semids = (int *) ids->elts;
  for (i = 0; i < ids->nelts; i++) {
    if (semids[i] == semid) {
      semids[i] = -1;
      break;
    }
  }

  res = counter_file_write(fh, ids);

  counter_file_lock(fh, LOCK_UN);
  return res;
}

static int counter_file_write(pr_fh_t *fh, array_header *ids) {
  register unsigned int i;
  int *elts;

  /* Write the list of IDs in the given array to the CounterFile,
   * overwriting any previous values.
   */

  if (counter_file_lock(fh, LOCK_EX) < 0) {
    (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
      "error write-locking CounterFile '%s': %s", fh->fh_path, strerror(errno));
  }

  if (pr_fsio_lseek(fh, 0, SEEK_SET) < 0) {
    int xerrno = errno;

    counter_file_lock(fh, LOCK_UN);
    errno = xerrno;

    return -1;
  }

  elts = (int *) ids->elts;
  for (i = 0; i < ids->nelts; i++) {
    char buf[32];

    /* Skip any negative IDs.  This small hack allows for IDs to be
     * effectively removed from the list.
     */
    if (elts[i] < 0)
      continue;

    memset(buf, '\0', sizeof(buf));
    snprintf(buf, sizeof(buf), "%d\n", elts[i]); 
    buf[sizeof(buf)-1] = '\0';
    buf[strlen(buf)-1] = '\0';

    if (pr_fsio_puts(buf, fh) < 0) {
      int xerrno = errno;

      counter_file_lock(fh, LOCK_UN);
      errno = xerrno;

      return -1;
    }
  }

  if (pr_fsio_ftruncate(fh, 0) < 0) {
    int xerrno = errno;

    counter_file_lock(fh, LOCK_UN);
    errno = xerrno;

    return -1;
  }

  if (counter_file_lock(fh, LOCK_SH) < 0) {
    (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
      "error unlocking CounterFile '%s': %s", fh->fh_path, strerror(errno));
  }

  return 0;
}

static pr_fh_t *counter_get_fh(pool *p, const char *path) {
  struct counter_fh *iter, *cfh = NULL;
  const char *abs_path;

  /* Find the CounterFile handle to use for the given path, if any. */

  if (counter_fhs == NULL) {
    errno = ENOENT;
    return NULL;
  }

  if (session.chroot_path) {
    abs_path = dir_abs_path(p, path, FALSE);

  } else {
    abs_path = path;
  }

  /* In order to handle globs, we do two passes.  On the first pass,
   * we look for the closest-matching glob area.  On the second pass,
   * we look for any closest-matching non-glob area.  This means that
   * exact matches override glob matches (as they should).
   */

  for (iter = (struct counter_fh *) counter_fhs->xas_list; iter;
     iter = iter->next) {

    if (!iter->isglob) {
      continue;
    }

    if (cfh == NULL) {
      /* Haven't found anything matching yet. */
      if (pr_fnmatch(iter->area, abs_path, 0) == 0) {
        cfh = iter;
      }

    } else {
      /* Have a previous match.  Is this a closer matching area? */
      if (iter->arealen > cfh->arealen &&
          pr_fnmatch(iter->area, abs_path, 0) == 0) {
        cfh = iter;
      }
    }
  }

  for (iter = (struct counter_fh *) counter_fhs->xas_list; iter;
     iter = iter->next) {

    if (iter->isglob) {
      continue;
    }

    if (cfh == NULL) {
      /* Haven't found anything matching yet. */
      if (strncmp(iter->area, abs_path, iter->arealen) == 0) {
        cfh = iter;
      }

    } else {
      /* Have a previous match.  Is this a closer matching area? */
      if (iter->arealen > cfh->arealen &&
          strncmp(iter->area, abs_path, iter->arealen) == 0) {
        cfh = iter;
      }
    }
  }

  if (cfh != NULL) {
    (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
      "using CounterFile '%s' covering area '%s' for path '%s'",
      cfh->fh->fh_path, cfh->area, path);
    return cfh->fh;
  }

  errno = ENOENT;
  return NULL;
}

static key_t counter_get_key(const char *path) {
  int res;
  struct stat st;

  /* ftok() uses stat(2) on the given path, which means that it needs to exist.
   * So stat() the file ourselves first, and create it if necessary.  We need
   * make sure that permissions on the file we create match the ones that
   * mod_xfer would create.
   */

  res = pr_fsio_stat(path, &st);
  if (res < 0 &&
      errno == ENOENT) {
    pr_fh_t *fh;

    fh = pr_fsio_open(path, O_WRONLY|O_CREAT);
    if (fh == NULL) {
      (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
      "error opening '%s': %s", path, strerror(errno));
      return -1;
    }

    pr_fsio_close(fh);
  }
    
  return ftok(path, COUNTER_PROJ_ID);
}

static int counter_get_sem(pr_fh_t *fh, const char *path) {
  int semid;
  key_t key;

  /* Obtain a key for this path. */
  key = counter_get_key(path);
  if (key == (key_t) -1) {
    (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
      "unable to get key for '%s': %s", path, strerror(errno));
    return -1;
  }

  /* Try first using IPC_CREAT|IPC_EXCL, to check if there is an existing
   * semaphore set for this key.  If there is, try again, using a flag of
   * zero.
   */
 
  semid = semget(key, COUNTER_NSEMS, IPC_CREAT|IPC_EXCL|0666);
  if (semid < 0) {
    if (errno == EEXIST) {
      semid = semget(key, 0, 0);

    } else {
      return -1;
    }

  } else {

    /* Set the values of the newly created semaphore to the configured
     * CounterMaxReaders and CounterMaxWriters.
     */
    if (counter_set_readers(semid) < 0) {
      (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
        "error setting readers (semaphore ID %d): %s", semid, strerror(errno));
    }

    if (counter_set_writers(semid) < 0) {
      (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
        "error setting writers (semaphore ID %d): %s", semid, strerror(errno));
    }

    if (counter_set_procs(semid) < 0) {
      (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
        "error setting procs (semaphore ID %d): %s", semid, strerror(errno));
    }

    /* Record the ID of the created semaphore in the CounterFile. */
    if (counter_file_add_id(fh, semid) < 0) {
      (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
        "error recording semaphore (semaphore ID %d) in CounterFile '%s': %s",
        semid, fh->fh_path, strerror(errno));
    }
  }

  return semid;
}

static int counter_remove_reader(pr_fh_t *fh, int semid) {
  struct sembuf s[2];

  s[0].sem_num = COUNTER_READER_SEMNO;
  s[0].sem_op = 1;
  s[0].sem_flg = IPC_NOWAIT|SEM_UNDO;

  s[1].sem_num = COUNTER_NPROCS_SEMNO;
  s[1].sem_op = 1;
  s[1].sem_flg = IPC_NOWAIT|SEM_UNDO;

  if (semop(semid, s, 2) < 0)
    return -1;

  if (semctl(semid, 0, IPC_RMID, s) < 0)
    return -1;

  return counter_file_remove_id(fh, semid);
}

static int counter_remove_writer(pr_fh_t *fh, int semid) {
  struct sembuf s[2];

  s[0].sem_num = COUNTER_WRITER_SEMNO;
  s[0].sem_op = 1;
  s[0].sem_flg = IPC_NOWAIT|SEM_UNDO;

  s[1].sem_num = COUNTER_NPROCS_SEMNO;
  s[1].sem_op = 1;
  s[1].sem_flg = IPC_NOWAIT|SEM_UNDO;

  if (semop(semid, s, 2) < 0)
    return -1;

  if (semctl(semid, 0, IPC_RMID, s) < 0)
    return -1;

  return counter_file_remove_id(fh, semid);
}

static int counter_set_procs(int semid) {
  union semun arg;

  arg.val = counter_max_readers + counter_max_writers;
  return semctl(semid, COUNTER_NPROCS_SEMNO, SETVAL, arg);
}

static int counter_set_readers(int semid) {
  union semun arg;

  arg.val = counter_max_readers;
  return semctl(semid, COUNTER_READER_SEMNO, SETVAL, arg);
}

static int counter_set_writers(int semid) {
  union semun arg;

  arg.val = counter_max_writers;
  return semctl(semid, COUNTER_WRITER_SEMNO, SETVAL, arg);
}

/* Configuration handlers
 */

/* usage: CounterEngine on|off */
MODRET set_counterengine(cmd_rec *cmd) {
  int bool;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[0]) = bool;
  
  return PR_HANDLED(cmd);
}

/* usage: CounterFile path */
MODRET set_counterfile(cmd_rec *cmd) {
  config_rec *c;
  const char *path;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|CONF_DIR);

  path = cmd->argv[1];
  if (*path != '/') {
    CONF_ERROR(cmd, "must be an absolute path");
  }

  /* In theory, we could open a filehandle on the configured path right
   * here, and fail if the file couldn't be created/opened.  Then we
   * could just stash that filehandle in the cmd_rec.  Easy.
   *
   * However, that would mean that we would have open descriptors for
   * vhosts to which the client may not connect.  We would also need to
   * use pr_fs_get_usable_fd() so that these filehandles don't use the wrong
   * fds.  Instead, then, we wait to open the filehandles in sess_init(),
   * where we know vhost to which the client connected.
   */

  c = add_config_param_str(cmd->argv[0], 1, path);
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* usage: CounterLog path|"none" */
MODRET set_counterlog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (pr_fs_valid_path(cmd->argv[1]) < 0) {
    CONF_ERROR(cmd, "must be an absolute path");
  }

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage:
 *  CounterMaxReaders max
 *  CounterMaxWriters max
 */
MODRET set_countermaxreaderswriters(cmd_rec *cmd) {
  int count;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|CONF_DIR);

  /* A count of zero means that an unlimited number of readers (or writers),
   * as is the default without this module, is in effect.
   */

  count = atoi(cmd->argv[1]);
  if (count < 0 ||
      count > INT_MAX) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "invalid number: ", cmd->argv[1],
      NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = count;
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET counter_retr(cmd_rec *cmd) {
  config_rec *c;
  int res;
  pr_fh_t *fh;

  if (!counter_engine)
    return PR_DECLINED(cmd);

  c = find_config(CURRENT_CONF, CONF_PARAM, "CounterMaxReaders", FALSE);
  counter_max_readers = c ? *((int *) c->argv[0]) : COUNTER_DEFAULT_MAX_READERS;

  if (counter_max_readers == 0)
    return PR_DECLINED(cmd);
 
  counter_curr_path = pr_table_get(cmd->notes, "mod_xfer.retr-path", NULL); 
  if (counter_curr_path == NULL) {
    return PR_DECLINED(cmd);
  }

  fh = counter_get_fh(cmd->tmp_pool, counter_curr_path);
  if (fh == NULL) {
    (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
      "%s: no CounterFile found for path '%s'", (char *) cmd->argv[0],
      counter_curr_path);

    /* No CounterFile configured/available for this path. */
    return PR_DECLINED(cmd);
  }

  counter_curr_semid = counter_get_sem(fh, counter_curr_path);
  if (counter_curr_semid < 0) {
    (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
      "unable to get semaphore for '%s': %s", counter_curr_path,
      strerror(errno));
    return PR_DECLINED(cmd);
  }

  /* Add a reader to this file by decrementing the reader counter value.
   * This functions as a sort of "lock".
   */
  res = counter_add_reader(counter_curr_semid);
  if (res < 0 &&
      errno == EAGAIN) {

    /* The lock acquisition failed, which means the file is busy.
     * The download should be failed.
     */
    (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
      "%s: max number of readers (%d) reached for '%s'", (char *) cmd->argv[0],
      counter_max_readers, counter_curr_path);
    pr_response_add_err(R_450, _("%s: File busy"), cmd->arg);
    return PR_ERROR(cmd);
  }

  counter_pending |= COUNTER_HAVE_READER;
  (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
    "%s: added reader counter for '%s' (semaphore ID %d)",
    (char *) cmd->argv[0], counter_curr_path, counter_curr_semid);

  return PR_DECLINED(cmd);
}

/* Handles the DELE, RNFR, and RNTO commands. */
MODRET counter_alter(cmd_rec *cmd) {
  config_rec *c;
  int res;
  pr_fh_t *fh;
  const char *path;

  if (!counter_engine)
    return PR_DECLINED(cmd);

  c = find_config(CURRENT_CONF, CONF_PARAM, "CounterMaxWriters", FALSE);
  counter_max_writers = c ? *((int *) c->argv[0]) : COUNTER_DEFAULT_MAX_WRITERS;

  if (counter_max_writers == 0)
    return PR_DECLINED(cmd);

  path = pr_fs_decode_path(cmd->tmp_pool, cmd->arg);

  if (!exists((char *) path)) {
    return PR_DECLINED(cmd);
  }

  /* The semaphores operate using dir_best_path(). */
  path = dir_best_path(cmd->tmp_pool, path);
  if (!path) {
    return PR_DECLINED(cmd);
  }

  counter_curr_path = path;

  fh = counter_get_fh(cmd->tmp_pool, counter_curr_path);
  if (fh == NULL) {
    (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
      "%s: no CounterFile found for path '%s'", (char *) cmd->argv[0],
      counter_curr_path);

    /* No CounterFile configured/available for this path. */
    return PR_DECLINED(cmd);
  }

  counter_curr_semid = counter_get_sem(fh, counter_curr_path);
  if (counter_curr_semid < 0) {
    (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
      "unable to get semaphore for '%s': %s", counter_curr_path,
      strerror(errno));
    return PR_DECLINED(cmd);
  }

  /* Add a writer to this file by decrementing the writer counter value.
   * This functions as a sort of "lock".
   */
  res = counter_add_writer(counter_curr_semid);
  if (res < 0 &&
      errno == EAGAIN) {
  
    /* The lock acquisition failed, which means the file is busy.
     * The upload should be failed.
     */
    (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
      "%s: max number of writers (%d) reached for '%s'", (char *) cmd->argv[0],
      counter_max_writers, counter_curr_path);
    pr_response_add_err(R_450, _("%s: File busy"), cmd->arg);
    return PR_ERROR(cmd);
  }

  counter_pending |= COUNTER_HAVE_WRITER;
  (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
    "%s: added writer counter for '%s' (semaphore ID %d)",
    (char *) cmd->argv[0], counter_curr_path, counter_curr_semid);

  return PR_DECLINED(cmd);
}

MODRET counter_stor(cmd_rec *cmd) {
  config_rec *c;
  int res;
  pr_fh_t *fh;

  if (!counter_engine)
    return PR_DECLINED(cmd);

  c = find_config(CURRENT_CONF, CONF_PARAM, "CounterMaxWriters", FALSE);
  counter_max_writers = c ? *((int *) c->argv[0]) : COUNTER_DEFAULT_MAX_WRITERS;

  if (counter_max_writers == 0)
    return PR_DECLINED(cmd);

  counter_curr_path = pr_table_get(cmd->notes, "mod_xfer.store-path", NULL);
  if (!counter_curr_path)
    return PR_DECLINED(cmd);

  fh = counter_get_fh(cmd->tmp_pool, counter_curr_path);
  if (fh == NULL) {
    (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
      "%s: no CounterFile found for path '%s'", (char *) cmd->argv[0],
      counter_curr_path);

    /* No CounterFile configured/available for this path. */
    return PR_DECLINED(cmd);
  }

  counter_curr_semid = counter_get_sem(fh, counter_curr_path);
  if (counter_curr_semid < 0) {
    (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
      "unable to get semaphore for '%s': %s", counter_curr_path,
      strerror(errno));
    return PR_DECLINED(cmd);
  }

  /* Add a writer to this file by decrementing the writer counter value.
   * This functions as a sort of "lock".
   */
  res = counter_add_writer(counter_curr_semid);
  if (res < 0 &&
      errno == EAGAIN) {
  
    /* The lock acquisition failed, which means the file is busy.
     * The upload should be failed.
     */
    (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
      "%s: max number of writers (%d) reached for '%s'", (char *) cmd->argv[0],
      counter_max_writers, counter_curr_path);
    pr_response_add_err(R_450, _("%s: File busy"), cmd->arg);
    return PR_ERROR(cmd);
  }

  counter_pending |= COUNTER_HAVE_WRITER;
  (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
    "%s: added writer counter for '%s' (semaphore ID %d)",
    (char *) cmd->argv[0], counter_curr_path, counter_curr_semid);

  return PR_DECLINED(cmd);
}

MODRET counter_reader_done(cmd_rec *cmd) {
  pr_fh_t *fh;

  if (!counter_engine)
    return PR_DECLINED(cmd);

  if (!(counter_pending & COUNTER_HAVE_READER))
    return PR_DECLINED(cmd);

  fh = counter_get_fh(cmd->tmp_pool, counter_curr_path);
  if (fh == NULL) {
    (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
      "%s: no CounterFile found for path '%s'", (char *) cmd->argv[0],
      counter_curr_path);

    /* No CounterFile configured/available for this path. */
    return PR_DECLINED(cmd);
  }

  if (counter_curr_semid == -1) {
    counter_curr_semid = counter_get_sem(fh, counter_curr_path);
    if (counter_curr_semid < 0) {
      (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
        "unable to get semaphore for '%s': %s", counter_curr_path,
        strerror(errno));
      return PR_DECLINED(cmd);
    }
  }

  if (counter_remove_reader(fh, counter_curr_semid) < 0) {
    (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
      "error removing reader for '%s': %s", counter_curr_path,
      strerror(errno));

  } else {
    (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
      "removed reader counter for '%s' (semaphore ID %d)", counter_curr_path,
      counter_curr_semid);

    counter_curr_path = NULL;
    counter_curr_semid = -1;
    counter_pending &= ~COUNTER_HAVE_READER;
  }

  return PR_DECLINED(cmd);
}

MODRET counter_writer_done(cmd_rec *cmd) {
  pr_fh_t *fh;

  if (!counter_engine)
    return PR_DECLINED(cmd);

  if (!(counter_pending & COUNTER_HAVE_WRITER))
    return PR_DECLINED(cmd);

  fh = counter_get_fh(cmd->tmp_pool, counter_curr_path);
  if (fh == NULL) {
    (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
      "%s: no CounterFile found for path '%s'", (char *) cmd->argv[0],
      counter_curr_path);

    /* No CounterFile configured/available for this path. */
    return PR_DECLINED(cmd);
  }

  if (counter_curr_semid == -1) {
    counter_curr_semid = counter_get_sem(fh, counter_curr_path);
    if (counter_curr_semid < 0) {
      (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
        "unable to get semaphore for '%s': %s", counter_curr_path,
        strerror(errno));
      return PR_DECLINED(cmd);
    }
  }

  if (counter_remove_writer(fh, counter_curr_semid) < 0) {
    (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
      "error removing writer for '%s': %s", counter_curr_path,
      strerror(errno));

  } else {
    (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
      "removed reader counter for '%s' (semaphore ID %d)", counter_curr_path,
      counter_curr_semid);

    counter_curr_path = NULL;
    counter_curr_semid = -1;
    counter_pending &= ~COUNTER_HAVE_WRITER;
  }

  return PR_DECLINED(cmd);
}

/* Event handlers
 */

#if defined(PR_SHARED_MODULE)
static void counter_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_counter.c", (const char *) event_data) == 0) {
    pr_event_unregister(&counter_module, NULL, NULL);

    if (counter_pool) {
      destroy_pool(counter_pool);
    }
  }
}
#endif

static void counter_exit_ev(const void *event_data, void *user_data) {
  pr_fh_t *fh;

  if (!counter_engine)
    return;

  if (counter_curr_semid != -1 &&
      (counter_pending & COUNTER_HAVE_READER)) {

    fh = counter_get_fh(counter_pool, counter_curr_path);
    if (fh != NULL) {
      counter_remove_reader(fh, counter_curr_semid);
    }
  }

  if (counter_curr_semid != -1 &&
      (counter_pending & COUNTER_HAVE_WRITER)) {
    if (fh == NULL) {
      fh = counter_get_fh(counter_pool, counter_curr_path);
    }

    if (fh != NULL) {
      counter_remove_writer(fh, counter_curr_semid);
    }
  }
}

static void counter_restart_ev(const void *event_data, void *user_data) {
  if (counter_pool)
    destroy_pool(counter_pool);

  counter_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(counter_pool, MOD_COUNTER_VERSION);
}

/* Initialization functions
 */

static int counter_init(void) {
  counter_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(counter_pool, MOD_COUNTER_VERSION);

#if defined(PR_SHARED_MODULE)
  pr_event_register(&counter_module, "core.module-unload",
    counter_mod_unload_ev, NULL);
#endif
  pr_event_register(&counter_module, "core.restart", counter_restart_ev,
    NULL);

  return 0;
}

static int counter_sess_init(void) {
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "CounterEngine", FALSE);
  if (c &&
      *((unsigned int *) c->argv[0]) == TRUE)
    counter_engine = TRUE;

  if (!counter_engine)
    return 0;

  c = find_config(main_server->conf, CONF_PARAM, "CounterLog", FALSE);
  if (c) {
    const char *path = c->argv[0];

    if (strcasecmp(path, "none") != 0) {
      int res, xerrno;

      PRIVS_ROOT
      res = pr_log_openfile(path, &counter_logfd, 0660);
      xerrno = errno;
      PRIVS_RELINQUISH;

      if (res < 0) {
        pr_log_debug(DEBUG2, MOD_COUNTER_VERSION
          ": error opening CounterLog '%s': %s", path, strerror(xerrno));
        counter_logfd = -1;
      }
    }
  }

  /* Find all CounterFile directives for this vhost, and make sure they
   * have open handles.  We need to do this here, and not in a POST_CMD
   * PASS handler because of the need to open handles that may be outside
   * of a chroot.
   */
  c = find_config(main_server->conf, CONF_PARAM, "CounterFile", TRUE);
  while (c != NULL) {
    int xerrno = 0;
    const char *area = NULL, *path;
    pr_fh_t *fh;
    struct counter_fh *cfh;

    pr_signals_handle();

    path = c->argv[0];

    if (c->parent != NULL) {
      if (c->parent->config_type == CONF_ANON ||
          c->parent->config_type == CONF_DIR) {
        area = c->parent->name;

      } else {
        (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
          "unhandled configuration parent type (%d) for CounterFile, skipping",
          c->parent->config_type);
        c = find_config_next(c, c->next, CONF_PARAM, "CounterFile", TRUE);
        continue;
      }

    } else {
      /* Toplevel CounterFile directive, in "server config" or <VirtualHost>
       * sections.
       */
      area = "/";
    }

    PRIVS_ROOT
    fh = pr_fsio_open(path, O_RDWR|O_CREAT);
    xerrno = errno;
    PRIVS_RELINQUISH

    if (fh == NULL) {
      pr_log_debug(DEBUG1, MOD_COUNTER_VERSION
        ": error opening CounterFile '%s': %s", path, strerror(xerrno));
      counter_engine = FALSE;

      if (counter_fhs != NULL) {
        for (cfh = (struct counter_fh *) counter_fhs->xas_list; cfh;
            cfh = cfh->next) {
          (void) pr_fsio_close(cfh->fh);
        }
      }

      return 0;
    }

    (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
      "opened CounterFile '%s'", path);

    if (counter_fhs == NULL) {
      counter_fhs = xaset_create(counter_pool, NULL);
    }

    cfh = pcalloc(counter_pool, sizeof(struct counter_fh));

    /* Ignore any trailing slash. */
    cfh->arealen = strlen(area);
    if (cfh->arealen > 1 &&
        area[cfh->arealen-1] == '/') {
      cfh->arealen--;
    }

    cfh->area = pstrndup(counter_pool, area, cfh->arealen);

    /* Mark any areas that use glob(3) characters. */
    if (strpbrk(cfh->area, "[*?") != NULL) {
      cfh->isglob = TRUE;
    }

    cfh->fh = fh;

    xaset_insert(counter_fhs, (xasetmember_t *) cfh);

    c = find_config_next(c, c->next, CONF_PARAM, "CounterFile", TRUE);
  }

  if (counter_fhs == NULL) {
    (void) pr_log_writefile(counter_logfd, MOD_COUNTER_VERSION,
      "no CounterFiles configured, disabling module");
    counter_engine = FALSE;
    return 0;
  }

  pr_event_register(&counter_module, "core.exit", counter_exit_ev, NULL);
  return 0;
}

/* Module API tables
 */

static conftable counter_conftab[] = {
  { "CounterEngine",		set_counterengine,		NULL },
  { "CounterFile",		set_counterfile,		NULL },
  { "CounterLog",		set_counterlog,			NULL },
  { "CounterMaxReaders",	set_countermaxreaderswriters,	NULL },
  { "CounterMaxWriters",	set_countermaxreaderswriters,	NULL },
  { NULL }
};

static cmdtable counter_cmdtab[] = {
  { CMD,	C_RETR,	G_NONE,	counter_retr,		FALSE,	FALSE },
  { CMD,	C_APPE,	G_NONE,	counter_stor,		FALSE,	FALSE },
  { CMD,	C_DELE,	G_NONE,	counter_alter,		FALSE,	FALSE },
  { CMD,	C_RNFR,	G_NONE,	counter_alter,		FALSE,	FALSE },
  { CMD,	C_RNTO,	G_NONE,	counter_alter,		FALSE,	FALSE },
  { CMD,	C_STOR, G_NONE, counter_stor,		FALSE,	FALSE },
  { LOG_CMD,	C_RETR,	G_NONE,	counter_reader_done,	FALSE,	FALSE },
  { LOG_CMD_ERR,C_RETR,	G_NONE,	counter_reader_done,	FALSE,	FALSE },
  { LOG_CMD,	C_APPE,	G_NONE,	counter_writer_done,	FALSE,	FALSE },
  { LOG_CMD_ERR,C_APPE,	G_NONE,	counter_writer_done,	FALSE,	FALSE },
  { LOG_CMD,	C_DELE,	G_NONE,	counter_writer_done,	FALSE,	FALSE },
  { LOG_CMD_ERR,C_DELE,	G_NONE,	counter_writer_done,	FALSE,	FALSE },
  { LOG_CMD,	C_RNTO,	G_NONE,	counter_writer_done,	FALSE,	FALSE },
  { LOG_CMD_ERR,C_RNTO,	G_NONE,	counter_writer_done,	FALSE,	FALSE },
  { LOG_CMD,	C_STOR,	G_NONE,	counter_writer_done,	FALSE,	FALSE },
  { LOG_CMD_ERR,C_STOR,	G_NONE,	counter_writer_done,	FALSE,	FALSE },

  { 0, NULL }
};

module counter_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "counter",

  /* Module configuration handler table */
  counter_conftab,

  /* Module command handler table */
  counter_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  counter_init,

  /* Session initialization function */
  counter_sess_init,

  /* Module version */
  MOD_COUNTER_VERSION
};
