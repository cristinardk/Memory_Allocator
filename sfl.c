#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <stdint.h>
#define DIE(assertion, call_description)				\
	do {								\
		if (assertion) {					\
			fprintf(stderr, "(%s, %d): ",			\
					__FILE__, __LINE__);		\
			perror(call_description);			\
			exit(errno);				        \
		}							\
	} while (0)

typedef struct info {
	unsigned int address;
	unsigned int dimmension;
	char *data;
} info;

typedef struct node_t {
	void *data;
	struct node_t *prev, *next;
} node_t;

typedef struct dbly_list {
	node_t *head;
	unsigned int data_size;
	unsigned int size;
	unsigned int address;
} dbly_list;

// Structura pentru alocarea de memorie
typedef struct {
	dbly_list **free_lists;
	unsigned int num_lists;
	unsigned int bytes_per_list;
	dbly_list *allocated_memory;
	int tip_reconstituire;
} memory_allocator;

dbly_list *dll_create(unsigned int data_size)
{
	dbly_list *list =
		(dbly_list *)malloc(sizeof(dbly_list));
	DIE(!list, "Error in dll_create: malloc failed");
	list->head = NULL;
	list->data_size = data_size;
	list->size = 0;
	return list;
}

node_t *dll_get_nth_node(dbly_list *list, unsigned int n)
{
	if (!list)
		return NULL;
	n %= list->size;
	node_t *wanted = list->head;
	if (n == 0)
		return wanted;
	if (n < list->size / 2) {
		for (unsigned int i = 0; i < n; i++)
			wanted = wanted->next;
	} else {
		for (unsigned int i = 0; i < list->size - n; i++)
			wanted = wanted->prev;
	}
	return wanted;
}

node_t *create_node(unsigned int address, unsigned int dimmension)
{
	node_t *new_node = (node_t *)malloc(sizeof(node_t));
	if (!new_node) {
		printf("Memory allocation failed!\n");
		exit(1);
	}
	// Alocăm memorie și inițializăm structura `info`
	info *node_info = (info *)malloc(sizeof(info));
	if (!node_info) {
		printf("Memory allocation for node info failed!\n");
		free(new_node);
		exit(1);
	}
	node_info->address = address;
	node_info->dimmension = dimmension;
	node_info->data = calloc(1, dimmension);
	// Atașăm structura `info` la nod
	new_node->data = node_info;
	new_node->prev = NULL;
	new_node->next = NULL;

	return new_node;
}

node_t *dll_remove_nth_node(dbly_list *list,
							unsigned int n)
{
	if (list->size == 0 || !list->head)
		return NULL;

	if (n >= list->size)
		n = list->size - 1;

	node_t *current = list->head;
	for (unsigned int i = 0; i < n && current->next; i++)
		current = current->next;
	if (current->prev)
		current->prev->next = current->next;
	else
		list->head = current->next;
	if (current->next)
		current->next->prev = current->prev;
	current->next = NULL;
	current->prev = NULL;
	list->size--;
	return current;
}

void init_heap_(memory_allocator *allocator,
				uintptr_t heap_base,
				unsigned int num_lists,
				unsigned int bytes_per_list,
				int tip_reconstituire)
{
	// Alocare spațiu pentru vectorul de liste dublu înlănțuite
	allocator->free_lists = malloc(num_lists * sizeof(dbly_list *));
	DIE(!allocator->free_lists, "malloc");
	allocator->num_lists = num_lists;
	allocator->bytes_per_list = bytes_per_list;
	// Inițializare fiecare listă dublu înlănțuită
	int exp = 3;
	for (unsigned int i = 0; i < num_lists; i++) {
		allocator->free_lists[i] = dll_create(1 << exp);
		allocator->free_lists[i]->size = bytes_per_list / (1 << exp);
		exp++;
	}
	// Adăugare adrese de început în fiecare listă
	uintptr_t current_address = heap_base;
	for (unsigned int i = 0; i < num_lists; i++) {
		dbly_list *current_list = allocator->free_lists[i];
		node_t *prev_node = NULL;
		for (unsigned int j = 0; j < current_list->size; j++) {
			node_t *new_node = malloc(sizeof(node_t));
			DIE(!new_node, "malloc");
			info *node_info = malloc(sizeof(info));
			DIE(!node_info, "malloc");
			node_info->dimmension = current_list->data_size;
			node_info->address = current_address;
			node_info->data = NULL;
			new_node->data = node_info;
			new_node->prev = prev_node;
			new_node->next = NULL;
			if (prev_node)
				prev_node->next = new_node;
			prev_node = new_node;
			if (!current_list->head)
				current_list->head = new_node;
			current_address += current_list->data_size;
		}
	}
	// Structură pentru păstrarea nodurilor alocate
	allocator->allocated_memory = malloc(sizeof(dbly_list));
	allocator->allocated_memory->head = NULL;
	allocator->allocated_memory->data_size = sizeof(info);
	allocator->tip_reconstituire = tip_reconstituire;
	allocator->allocated_memory->size = 0;
}

void parse_init_heap(char *heap_base_str, char *nr_lists_str,
					 char *bytes_per_list_str, char *tip_reconstituire_str,
					 memory_allocator **allocator)
{
	unsigned int heap_base = (unsigned int)strtoul(heap_base_str, NULL, 0);
	unsigned int num_lists = (unsigned int)strtoul(nr_lists_str, NULL, 0);
	unsigned int bytes_list = (unsigned int)strtoul(bytes_per_list_str,
													NULL, 0);
	int tip_reconstituire = atoi(tip_reconstituire_str);
	*allocator = malloc(sizeof(memory_allocator));
	DIE(!(*allocator), "malloc");
	init_heap_(*allocator, heap_base, num_lists, bytes_list, tip_reconstituire);
}

int compare_allocated_blocks(const void *a, const void *b)
{
	const node_t *node_a = *(const node_t **)a;
	const node_t *node_b = *(const node_t **)b;
	const info *info_a = (const info *)node_a->data;
	const info *info_b = (const info *)node_b->data;
	if (info_a->address > info_b->address)
		return 1;
	if (info_a->address < info_b->address)
		return -1;
	return 0;
}

int cmp_free_lists(const void *a, const void *b)
{
	const dbly_list *list_a = *(const dbly_list **)a;
	const dbly_list *list_b = *(const dbly_list **)b;
	return (list_a->data_size > list_b->data_size) -
			(list_a->data_size < list_b->data_size);
}

void sort_memory(dbly_list *list)
{
	unsigned int list_size = list->size;
	node_t **nodes_array = (node_t **)malloc(list_size * sizeof(node_t *));
	DIE(!nodes_array, "malloc");

	unsigned int index = 0;
	node_t *current_node = list->head;
	while (current_node) {
		nodes_array[index++] = current_node;
		current_node = current_node->next;
	}
	qsort(nodes_array, index, sizeof(node_t *), compare_allocated_blocks);

	list->head = nodes_array[0];
	list->head->prev = NULL;
	for (unsigned int i = 0; i < index - 1; ++i) {
		nodes_array[i]->next = nodes_array[i + 1];
		nodes_array[i + 1]->prev = nodes_array[i];
	}
	nodes_array[index - 1]->next = NULL;
	free(nodes_array);
}

void no_fragmentation(memory_allocator *allocator,
					  dbly_list *chosen_list, node_t *chosen_node)
{
	node_t *new_node = create_node(((info *)chosen_node->data)->address,
									((info *)chosen_node->data)->dimmension);
	new_node->next = allocator->allocated_memory->head;
	if (allocator->allocated_memory->head)
		allocator->allocated_memory->head->prev = new_node;
	allocator->allocated_memory->head = new_node;
	allocator->allocated_memory->size++;
	node_t *removed = dll_remove_nth_node(chosen_list, 0);
	free(((info *)removed->data)->data);
	free(removed->data);
	free(removed);
}

void allocator_in_free_list(memory_allocator *allocator,
							node_t *frag_block)
{
	int index = -1;
	for (unsigned int i = 0; i < allocator->num_lists; i++) {
		if (allocator->free_lists[i]->data_size ==
			((info *)frag_block->data)->dimmension) {
			index = i;
			break;
		}
	}
	if (index == -1) {
		dbly_list *new_list =
			dll_create(sizeof(dbly_list));
		DIE(!new_list, "dll_create failed");
		node_t *new_node = create_node(((info *)frag_block->data)->address,
			((info *)frag_block->data)->dimmension);
		new_node->next = new_list->head;
		if (new_list->head)
			new_list->head->prev = new_node;
		new_list->head = new_node;
		new_list->size++;
		allocator->num_lists++;
		allocator->free_lists = realloc(allocator->free_lists,
										allocator->num_lists *
										sizeof(dbly_list *));
		DIE(!allocator->free_lists, "realloc failed");

		allocator->free_lists[allocator->num_lists - 1] = new_list;
		allocator->free_lists[allocator->num_lists - 1]->data_size =
			((info *)frag_block->data)->dimmension;
		allocator->free_lists[allocator->num_lists - 1]->size++;
	} else {
		node_t *new_node = create_node(((info *)frag_block->data)->address,
										((info *)frag_block->data)->dimmension);
		new_node->next = allocator->free_lists[index]->head;
		if (allocator->free_lists[index]->head)
			allocator->free_lists[index]->head->prev = new_node;
		allocator->free_lists[index]->head = new_node;
		allocator->free_lists[index]->size++;
		//Sortez lista nou creata
		sort_memory(allocator->free_lists[index]);
	}

	qsort(allocator->free_lists, allocator->num_lists, sizeof(dbly_list *),
		  cmp_free_lists);
}

void fragmentation(memory_allocator *allocator,
				   dbly_list *chosen_list,
				   node_t *chosen_node, unsigned int memory)
{
	node_t *fragmented_nod;
	fragmented_nod = create_node(((info *)chosen_node->data)->address,
								 ((info *)chosen_node->data)->dimmension);
	((info *)fragmented_nod->data)->address =
		((info *)chosen_node->data)->address + memory;
	((info *)fragmented_nod->data)->dimmension =
		((info *)chosen_node->data)->dimmension - memory;
	((info *)chosen_node->data)->dimmension = memory;
	no_fragmentation(allocator, chosen_list, chosen_node);
	if (fragmented_nod->next)
		fragmented_nod->next->prev = fragmented_nod;
	allocator_in_free_list(allocator, fragmented_nod);
	free(((info *)fragmented_nod->data)->data);
	free(fragmented_nod->data);
	free(fragmented_nod);
}

void malloc_memory(memory_allocator *allocator, unsigned int memory,
				   unsigned int *num_fragmentation, unsigned int *num_malloc)
{
	if (memory == 0) {
		printf("Cannot allocate 0 bytes.\n");
		return;
	}
	node_t *chosen_node = NULL;
	dbly_list *chosen_list = NULL;
	int found = 0;
	// Căutăm în listele de blocuri libere pentru un bloc suficient de mare
	for (unsigned int i = 0; i < allocator->num_lists; i++) {
		if (allocator->free_lists[i]->data_size >= memory &&
			allocator->free_lists[i]->size > 0) {
			for (node_t *node = allocator->free_lists[i]->head; node;
				node = node->next) {
				if (((info *)node->data)->dimmension >= memory) {
					chosen_node = node;
					chosen_list = allocator->free_lists[i];
					found = 1;
					break;
				}
			}
		if (found)
			break;
		}
	}
	if (!found) {
		printf("Out of memory\n");
		return;
	}
	if (chosen_list->data_size <= memory) {
		no_fragmentation(allocator, chosen_list, chosen_node);
	} else {
		fragmentation(allocator, chosen_list, chosen_node, memory);
		(*num_fragmentation)++;
	}
	sort_memory(allocator->allocated_memory);

	(*num_malloc)++;
}

void free_memory(memory_allocator *allocator, unsigned int address,
				 unsigned int *num_free)
{
	if (!address)
		return;
	int found = 0;
	node_t *prev_node = NULL;
	node_t *current_node = allocator->allocated_memory->head;
	node_t *chosen_node = NULL;
	int i = 0;
	while (current_node) {
		i++;
		if (((info *)current_node->data)->address == address) {
			chosen_node = current_node;
			found = 1;
			break;
		}
		prev_node = current_node;
		current_node = current_node->next;
	}
	if (!found) {
		printf("Invalid free\n");
		return;
	}
	allocator_in_free_list(allocator, chosen_node);
	if (prev_node)
		prev_node->next = current_node->next;
	else
		allocator->allocated_memory->head = current_node->next;
	if (current_node->next)
		current_node->next->prev = prev_node;

	allocator->allocated_memory->size--;
	free(((info *)chosen_node->data)->data);
	free(chosen_node->data);
	free(chosen_node);
	(*num_free)++;
}

void destroy_heap(memory_allocator *allocator)
{
	if (!allocator)
		return;
	for (unsigned int i = 0; i < allocator->num_lists; i++) {
		node_t *current_node = allocator->free_lists[i]->head;
		while (current_node) {
			node_t *next_node = current_node->next;
			free(((info *)current_node->data)->data);
			free(current_node->data);
			free(current_node);
			current_node = next_node;
		}
		free(allocator->free_lists[i]);
	}

	free(allocator->free_lists);

	node_t *allocated_node = allocator->allocated_memory->head;
	while (allocated_node) {
		node_t *next_allocated_node = allocated_node->next;
		free(((info *)allocated_node->data)->data);
		free(allocated_node->data);
		free(allocated_node);
		allocated_node = next_allocated_node;
	}

	free(allocator->allocated_memory);
	free(allocator);
}

void dump_memory(memory_allocator *allocator, int *num_malloc,
				 int *num_free, int *num_fragmentations)
{
	printf("+++++DUMP+++++\n");
	unsigned int total_memory = 0;
	unsigned int total_allocated_memory = 0;
	unsigned int total_free_memory = 0;
	unsigned int nr_free_blocks = 0;
	unsigned int nr_allocated_blocks = 0;
	unsigned int nr_malloc_calls = *num_malloc;
	unsigned int nr_free_calls = *num_free;
	unsigned int nr_fragmentations = *num_fragmentations;
	for (unsigned int i = 0; i < allocator->num_lists; ++i) {
		node_t *current_node = allocator->free_lists[i]->head;
		while (current_node) {
			info *block_info = (info *)current_node->data;
			total_free_memory += block_info->dimmension;
			total_memory += block_info->dimmension;
			nr_free_blocks++;
			current_node = current_node->next;
		}
	}
	node_t *allocated_node = allocator->allocated_memory->head;
	while (allocated_node) {
		info *allocated_info = (info *)allocated_node->data;
		total_allocated_memory += allocated_info->dimmension;
		total_memory += allocated_info->dimmension;
		nr_allocated_blocks++;
		allocated_node = allocated_node->next;
	}
	printf("Total memory: %u bytes\n", total_memory);
	printf("Total allocated memory: %u bytes\n", total_allocated_memory);
	printf("Total free memory: %u bytes\n",
		   total_memory - total_allocated_memory);
	printf("Free blocks: %u\n", nr_free_blocks);
	printf("Number of allocated blocks: %u\n", nr_allocated_blocks);
	printf("Number of malloc calls: %u\n", nr_malloc_calls);
	printf("Number of fragmentations: %u\n", nr_fragmentations);
	printf("Number of free calls: %u\n", nr_free_calls);
	for (unsigned int i = 0; i < allocator->num_lists; ++i) {
		unsigned int block_size = allocator->free_lists[i]->data_size;
		unsigned int nr_blocks = 0;
		node_t *count_node = allocator->free_lists[i]->head;
		while (count_node) {
			nr_blocks++;
			count_node = count_node->next;
		}
		if (nr_blocks == 0) {
			continue;
		} else {
			printf("Blocks with %u bytes - %u free block(s) : ",
				   block_size, nr_blocks);
			node_t *current_node = allocator->free_lists[i]->head;
			while (current_node) {
				info *block_info = (info *)current_node->data;
				if (!current_node->next)
					printf("0x%x", block_info->address);
				else
					printf("0x%x ", block_info->address);
				current_node = current_node->next;
			}
			printf("\n");
		}
	}
	printf("Allocated blocks :");
	allocated_node = allocator->allocated_memory->head;
	while (allocated_node) {
		info *allocated_info = (info *)allocated_node->data;
		printf(" (0x%x - %u)", allocated_info->address,
			   allocated_info->dimmension);
		allocated_node = allocated_node->next;
	}
	printf("\n-----DUMP-----\n");
}

void write_memory(memory_allocator *allocator, unsigned int address,
				  char *data, unsigned int nr_bytes, unsigned int *num_malloc,
				  unsigned int *num_free, unsigned int *num_fragmentations,
				  int *seg)
{
	int found = 0;
	unsigned int bytes_towrite = 0;
	unsigned int address_aux;
	unsigned int total_memory = 0;
	node_t *selected_node = allocator->allocated_memory->head;
	for (node_t *node = allocator->allocated_memory->head; node;
		node = node->next) {
		if (address == ((info *)node->data)->address) {
			found = 1;
			total_memory = ((info *)node->data)->dimmension;
			address_aux = ((info *)node->data)->address;
			while (node->next) {
				if (address_aux + ((info *)node->data)->dimmension
					!= ((info *)node->next->data)->address)
					break;
				address_aux += ((info *)node->data)->dimmension;
				node = node->next;
				total_memory += ((info *)node->data)->dimmension;
			}
			if (nr_bytes > strlen(data))
				nr_bytes = strlen(data);
			if (nr_bytes > total_memory) {
				found = 0;
				break;
			}
			while (nr_bytes) {
				if (!((info *)selected_node->data)->data)
					((info *)selected_node->data)->data =
						malloc(((info *)selected_node->data)->dimmension);
				bytes_towrite = (nr_bytes <
								((info *)selected_node->data)->dimmension) ?
								nr_bytes :
								((info *)selected_node->data)->dimmension;
				memcpy(((info *)selected_node->data)->data, data,
					   bytes_towrite);
				data += bytes_towrite;
				nr_bytes -= bytes_towrite;
				selected_node = selected_node->next;
			}
			break;
		}
		selected_node =  selected_node->next;
	}
	if (!found) {
		printf("Segmentation fault (core dumped)\n");
		dump_memory(allocator, num_malloc, num_free, num_fragmentations);
		destroy_heap(allocator);
		(*seg)++;
	}
}

void read(memory_allocator *allocator, unsigned int address,
		  unsigned int nr_bytes, unsigned int *num_malloc,
		  unsigned int *num_free, unsigned int *num_fragmentations, int *seg)
{
	int found = 0;
	unsigned int bytes_to_read = 0;
	unsigned int address_aux;
	unsigned int total_memory = 0;
	node_t *selected_node = allocator->allocated_memory->head;
	for (node_t *node = allocator->allocated_memory->head; node;
		node = node->next) {
		if (address == ((info *)node->data)->address) {
			found = 1;
			total_memory = ((info *)node->data)->dimmension;
			address_aux = ((info *)node->data)->address;
			while (node->next) {
				if (address_aux + ((info *)node->data)->dimmension
					!= ((info *)node->next->data)->address) {
					break;
				}
				address_aux += ((info *)node->data)->dimmension;
				node = node->next;
				total_memory += ((info *)node->data)->dimmension;
			}
			if (nr_bytes > total_memory) {
				found = 0;
				break;
			}
			while (nr_bytes) {
				bytes_to_read = (nr_bytes <
								((info *)selected_node->data)->dimmension)
								? nr_bytes
								: ((info *)selected_node->data)->dimmension;
				for (int i = 0; i < bytes_to_read; i++)
					printf("%c", *(((info *)selected_node->data)->data + i));
				nr_bytes -= bytes_to_read;
				selected_node = selected_node->next;
			}
			printf("\n");
			break;
		}
		selected_node =  selected_node->next;
	}

	if (!found) {
		printf("Segmentation fault (core dumped)\n");
		dump_memory(allocator, num_malloc, num_free, num_fragmentations);
		destroy_heap(allocator);
		(*seg)++;
	}
}

int main(void)
{
	memory_allocator *allocator = NULL;
	char command[600];
	int nr_malloc = 0;
	int nr_free = 0;
	int nr_fragmentation = 0;
	while (1) {
		scanf("%s", command);
		if (strcmp(command, "INIT_HEAP") == 0) {
			char heap_base_str[100];
			char num_lists_str[100];
			char bytes_per_list_str[100];
			char tip_reconstituire_str[100];
			scanf(" %s %s %s %s", heap_base_str, num_lists_str,
				  bytes_per_list_str, tip_reconstituire_str);
			parse_init_heap(heap_base_str, num_lists_str,
							bytes_per_list_str, tip_reconstituire_str,
							&allocator);
		} else if (strcmp(command, "MALLOC") == 0) {
			int memory;
			scanf("%d", &memory);
			malloc_memory(allocator, memory, &nr_fragmentation, &nr_malloc);
		} else if (strcmp(command, "FREE") == 0) {
			char address_str[100];
			scanf(" %s", address_str);
			unsigned int address = (unsigned int)strtoul(address_str, NULL, 0);
			free_memory(allocator, address, &nr_free);
		} else if (strcmp(command, "READ") == 0) {
			unsigned int address;
			unsigned int nr_bytes;
			char address_str[100];
			int seg = 0;
			scanf("%s", address_str);
			address = (unsigned int)strtoul(address_str, NULL, 0);
			scanf("%u", &nr_bytes);
			read(allocator, address, nr_bytes, &nr_malloc,
				 &nr_free, &nr_fragmentation, &seg);
			if (seg)
				break;
		} else if (strcmp(command, "WRITE") == 0) {
			unsigned int address;
			char data[512];
			unsigned int nr_bytes;
			char address_str[100];
			int seg = 0;
			scanf("%s", address_str);
			address = (unsigned int)strtoul(address_str, NULL, 0);
			scanf(" \"%511[^\"]\" %u", data, &nr_bytes);
			write_memory(allocator, address, data, nr_bytes,
						 &nr_malloc, &nr_free, &nr_fragmentation, &seg);
			if (seg)
				break;
		} else if (strcmp(command, "DESTROY_HEAP") == 0) {
			destroy_heap(allocator);
			break;
		} else if (strcmp(command, "DUMP_MEMORY") == 0) {
			dump_memory(allocator, &nr_malloc, &nr_free, &nr_fragmentation);
		} else {
			printf("Comanda necunoscuta\n");
		}
	}
	return 0;
}
