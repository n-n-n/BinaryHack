#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define LOG_OUT
#ifdef LOG_OUT
#define LOG(...) printf(__FUNCTION__);printf(": ");printf(__VA_ARGS__)
#else
#define LOG(...)
#endif

typedef struct _link_list_t
{
    void* item;
    struct _link_list_t* next;
} link_list_t;


int get_size(link_list_t *list)
{
    int i = 0;
    LOG("item 0x%08X \n", list);
    while (NULL != list) {
       LOG("check ITEM 0x%08X, 0x%08X \n", list, list->next);
        list = list->next;
        i += 1;
    }
    return i;
}
link_list_t* add_item(link_list_t *list, void* item_ptr, size_t size)
{
    link_list_t *prev = list;
    LOG("item 0x%08X \n", list);
    while (NULL != list) {
        LOG("check ITEM 0x%08X, 0x%08X \n", list, list->next);
        prev = list;
        list = list->next;
    }


    LOG("TO ADDED ITEM 0x%08X \n", list);
    list = malloc(sizeof(link_list_t));
    if (NULL != prev) {
        prev->next = list;
    }
    list->item = malloc(size);
    list->next = NULL;
    memcpy(list->item, item_ptr, size);

    LOG("ADDED ITEM 0x%08X \n", list);
    LOG("== after OBJECT FILE SIZE: %d\n", get_size(list));
    return list;
}

void delete_all_items(link_list_t* list)
{
    link_list_t* prev = NULL;
    while (NULL != list) {
        LOG("next\n");
        free(list->item);
        free(prev);
        prev = list;
        list = list->next;
    }
}

unsigned char* load_file(const char* file);

/*
 archive file (*.a) loading test
 */
int main()
{
    int i;
    link_list_t* lst = NULL;
    for (i = 0; i < 2; i++) {

        if (NULL == lst) {
            LOG("Add first:%d\n", (int)i);
            lst = add_item(lst, &i, sizeof(i));
            LOG("item 0x%08X \n", lst);
        } else {
            LOG("Add :%d\n", (int)i);
            add_item(lst, &i, sizeof(i));
            LOG("item 0x%08X \n", lst);
        }

    }

    link_list_t* list = lst;
    while(NULL != list) 
    {
        i = *(int**)(list->item);
        LOG("i;%d\n", (int)i);
        list = list->next;
    }
    delete_all_items(lst);

    return 0;
}
