#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "lwip/sys.h"
#include "cc.h"
#include "sys_arch.h"

void
sys_init(void)
{
}

err_t
sys_sem_new(sys_sem_t *sem, u8_t count)
{
  sem = malloc (sizeof (sys_sem_t));
  if (!sem) {
    return ERR_MEM;
  }

  sema_init (sem, count);

  return ERR_OK;
}

void
sys_sem_free(sys_sem_t *sem)
{
  free (sem);
}

void
sys_sem_signal(sys_sem_t *sem)
{
  sema_up (sem);
}

u32_t
sys_arch_sem_wait(sys_sem_t *sem, u32_t timeout)
{
  // TODO: implement timeout
  sema_down (sem);
  return 0;
}

int
sys_sem_valid(sys_sem_t *sem)
{
  return (sem != NULL);
}

void
sys_sem_set_invalid(sys_sem_t *sem)
{
  sem = NULL;
}

err_t
sys_mbox_new(sys_mbox_t *mbox, int size)
{
  mbox = malloc (sizeof (sys_mbox_t));
  mbox->size = size;
  sema_init (&mbox->wait, 0);
  list_init (&mbox->queue);

  return ERR_OK;
}

void
sys_mbox_free(sys_mbox_t *mbox)
{
  // TODO: ensure there are no messages still in the mailbox
  free (mbox);
}

void
sys_mbox_post(sys_mbox_t *mbox, void *msg)
{
  struct mbox_entry *entry = malloc (sizeof (struct mbox_entry));
  entry->msg = msg;

  list_push_back (&mbox->queue, &entry->elem);
  sema_up (&mbox->wait);
}

u32_t
sys_arch_mbox_fetch(sys_mbox_t *mbox, void **msg, u32_t timeout)
{
  struct mbox_entry *entry;

  if (!list_empty (&mbox->queue)) {
    // TODO: implement timeout
    sema_down (&mbox->wait);

    entry = list_entry (list_pop_front (&mbox->queue), struct mbox_entry, elem);
    msg = &entry->msg;
  }
}

u32_t
sys_arch_mbox_tryfetch(sys_mbox_t *mbox, void **msg)
{
   if (!list_empty (&mbox->queue)) {
    struct mbox_entry *entry;

    entry = list_entry (list_pop_front (&mbox->queue), struct mbox_entry, elem);
    msg = &entry->msg;

    return 0;
  }
  else {
    return SYS_MBOX_EMPTY;
  }
}

err_t
sys_mbox_trypost(sys_mbox_t *mbox, void *msg)
{
  sys_mbox_post (mbox, msg);
  return ERR_OK;
}

int
sys_mbox_valid(sys_mbox_t *mbox)
{
  return (mbox != NULL);
}

void
sys_mbox_set_invalid(sys_mbox_t *mbox)
{
  mbox = NULL;
}

sys_thread_t
sys_thread_new(const char *name, lwip_thread_fn thread, void *arg, int stacksize UNUSED, int prio)
{
  return thread_create (name, prio, thread, arg);
}

