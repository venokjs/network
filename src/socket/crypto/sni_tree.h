#ifndef VENOK_SNI_TREE_H
#define VENOK_SNI_TREE_H

#ifndef VENOK_NO_SSL
void *sni_new();
void sni_free(void *sni, void(*cb)(void *));
int sni_add(void *sni, const char *hostname, void *user);
void *sni_remove(void *sni, const char *hostname);
void *sni_find(void *sni, const char *hostname);
#endif

#endif //VENOK_SNI_TREE_H
