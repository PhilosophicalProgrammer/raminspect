struct pointer_list {
    size_t length;
    size_t capacity;
    uintptr_t* data;
};

static void push_pointer(struct pointer_list* buffer, uintptr_t address) {
    if(buffer -> data == NULL) {
        buffer -> capacity = 100;
        buffer -> data = kmalloc(buffer -> capacity * sizeof(uintptr_t), GFP_KERNEL);
    }

    if(buffer -> length == buffer -> capacity) {
        buffer -> capacity *= 2;
        uintptr_t new_buf_size = buffer -> capacity * sizeof(uintptr_t);
        uintptr_t* old_buffer = buffer -> data;

        uintptr_t* new_buffer = kmalloc(new_buf_size, GFP_KERNEL);
        memcpy(new_buffer, old_buffer, (buffer -> length) * sizeof(uintptr_t));
        buffer -> data = new_buffer;
        kfree(old_buffer);
    }

    (buffer -> length)++;
    (buffer -> data)[buffer -> length - 1] = address;
}

static void swap_remove_index(struct pointer_list* buffer, uintptr_t index) {
    if(buffer -> length > 1) {
        (buffer -> data)[index] = (buffer -> data)[buffer -> length - 1];
    }

    (buffer -> length)--;
}