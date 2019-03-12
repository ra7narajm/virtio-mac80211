#ifndef __WIFIMEDIUM_DOUBLE_LINK_LIST_H_
#define __WIFIMEDIUM_DOUBLE_LINK_LIST_H_
/* GPL 2.0 */

/* minial copy of Linux double link list imple */

struct list_head {
	struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
        struct list_head name = LIST_HEAD_INIT(name)

static inline void INIT_LIST_HEAD(struct list_head *list)
{
        list->next = list;
        list->prev = list;
}

static inline void __list_add(struct list_head *nnode,
                              struct list_head *prev,
                              struct list_head *next)
{
        next->prev = nnode;
        nnode->next = next;
        nnode->prev = prev;
        prev->next = nnode;
}

static inline void list_add(struct list_head *nnode, struct list_head *head)
{
        __list_add(nnode, head, head->next);
}

static inline void __list_del(struct list_head * prev, struct list_head * next)
{
        next->prev = prev;
        prev->next = next;
}

static inline void list_del(struct list_head *entry)
{
        __list_del(entry->prev, entry->next);
}

#endif //__WIFIMEDIUM_DOUBLE_LINK_LIST_H_
