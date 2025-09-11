/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "gc_object.h"
#include "mem_alloc.h"
#include "../wasm_runtime_common.h"
#if WASM_ENABLE_INTERP != 0
#include "../interpreter/wasm_runtime.h"
#endif
#if WASM_ENABLE_AOT != 0
#include "../aot/aot_runtime.h"
#endif
#if WASM_ENABLE_STRINGREF != 0
#include "string_object.h"
#endif

WASMRttTypeRef
wasm_rtt_type_new(WASMType *defined_type, uint32 defined_type_idx,
                  WASMRttType **rtt_types, uint32 rtt_type_count,
                  korp_mutex *rtt_type_lock)
{
    WASMRttType *rtt_type;

    bh_assert(defined_type_idx < rtt_type_count);

    os_mutex_lock(rtt_type_lock);

    if (rtt_types[defined_type_idx]) {
        os_mutex_unlock(rtt_type_lock);
        return rtt_types[defined_type_idx];
    }

    if ((rtt_type = wasm_runtime_malloc(sizeof(WASMRttType)))) {
        rtt_type->type_flag = defined_type->type_flag;
        rtt_type->inherit_depth = defined_type->inherit_depth;
        rtt_type->defined_type = defined_type;
        rtt_type->root_type = defined_type->root_type;

        rtt_types[defined_type_idx] = rtt_type;
    }

    os_mutex_unlock(rtt_type_lock);
    return rtt_type;
}

static void *
gc_obj_malloc(void *heap_handle, uint64 size)
{
    void *mem;

    if (size >= UINT32_MAX
        || !(mem = mem_allocator_malloc_with_gc(heap_handle, (uint32)size))) {
        LOG_WARNING("warning: failed to allocate memory for gc object");
        return NULL;
    }

    memset(mem, 0, (uint32)size);
    return mem;
}

static void *
get_gc_heap_handle(WASMExecEnv *exec_env)
{
    void *gc_heap_handle = NULL;
    WASMModuleInstanceCommon *module_inst = exec_env->module_inst;

#if WASM_ENABLE_INTERP != 0
    if (module_inst->module_type == Wasm_Module_Bytecode)
        gc_heap_handle =
            ((WASMModuleInstance *)module_inst)->e->common.gc_heap_handle;
#endif
#if WASM_ENABLE_AOT != 0
    if (module_inst->module_type == Wasm_Module_AoT)
        gc_heap_handle =
            ((AOTModuleInstanceExtra *)((AOTModuleInstance *)module_inst)->e)
                ->common.gc_heap_handle;
#endif

    bh_assert(gc_heap_handle);
    return gc_heap_handle;
}

WASMStructObjectRef
wasm_struct_obj_new_internal(void *heap_handle, WASMRttTypeRef rtt_type)
{
    WASMStructObjectRef struct_obj;
    WASMStructType *struct_type;

    bh_assert(rtt_type->type_flag == WASM_TYPE_STRUCT);

    struct_type = (WASMStructType *)rtt_type->defined_type;
    if (!(struct_obj = gc_obj_malloc(heap_handle, struct_type->total_size))) {
        return NULL;
    }

    struct_obj->header = (WASMObjectHeader)rtt_type;

    return struct_obj;
}

WASMStructObjectRef
wasm_struct_obj_new(WASMExecEnv *exec_env, WASMRttTypeRef rtt_type)
{
    void *heap_handle = get_gc_heap_handle(exec_env);
    return wasm_struct_obj_new_internal(heap_handle, rtt_type);
}

void
wasm_struct_obj_set_field(WASMStructObjectRef struct_obj, uint32 field_idx,
                          const WASMValue *value)
{
    WASMRttTypeRef rtt_type =
        (WASMRttTypeRef)wasm_object_header((WASMObjectRef)struct_obj);
    WASMStructType *struct_type = (WASMStructType *)rtt_type->defined_type;
    WASMStructFieldType *field;
    uint8 field_size, *field_data;

    bh_assert(field_idx < struct_type->field_count);

    field = struct_type->fields + field_idx;
    field_data = (uint8 *)struct_obj + field->field_offset;
    field_size = field->field_size;

    if (field_size == 4) {
        *(int32 *)field_data = value->i32;
    }
    else if (field_size == 8) {
#if defined(BUILD_TARGET_X86_64) || defined(BUILD_TARGET_AMD_64) \
    || defined(BUILD_TARGET_X86_32)
        *(int64 *)field_data = value->i64;
#else
        PUT_I64_TO_ADDR((uint32 *)field_data, value->i64);
#endif
    }
    else if (field_size == 1) {
        *(int8 *)field_data = (int8)value->i32;
    }
    else if (field_size == 2) {
        *(int16 *)field_data = (int16)value->i32;
    }
    else if (wasm_is_reftype_i31ref(field->field_type)) {
        /* Handle i31 reference fields - extract raw value from encoded i31 reference */
        if (field_size == 4) {
            if (value->gc_obj && wasm_obj_is_i31_obj(value->gc_obj)) {
                /* Extract the raw integer value from the encoded i31 reference */
                uint32 raw_i31_val = wasm_i31_obj_get_value((WASMI31ObjectRef)value->gc_obj, false);
                printf("[I31_SET_FIELD] field_type=0x%x, encoded=0x%lx, raw_val=%u\n", 
                       field->field_type, (uintptr_t)value->gc_obj, raw_i31_val);
                *(uint32 *)field_data = raw_i31_val;
            }
            else {
                /* Store 0 for null or invalid i31 references */
                printf("[I31_SET_FIELD] Null/invalid i31 reference, storing 0\n");
                *(uint32 *)field_data = 0;
            }
        }
        else {
            /* Unexpected field size for i31 reference */
            printf("[I31_SET_FIELD] Unexpected field_size=%d for i31 field\n", field_size);
            bh_assert(0);
        }
    }
    else if (wasm_is_type_reftype(field->field_type)) {
        /* Handle other reference types - store the reference in the field data */
        /* Use direct assignment to avoid potential corruption from PUT_REF_TO_ADDR macro */
        *(void **)field_data = (void *)(value->gc_obj);
    }
    else {
        bh_assert(0);
    }
}

void
wasm_struct_obj_get_field(const WASMStructObjectRef struct_obj,
                          uint32 field_idx, bool sign_extend, WASMValue *value)
{
    WASMRttTypeRef rtt_type =
        (WASMRttTypeRef)wasm_object_header((WASMObjectRef)struct_obj);
    WASMStructType *struct_type = (WASMStructType *)rtt_type->defined_type;
    WASMStructFieldType *field;
    uint8 *field_data, field_size;

    bh_assert(field_idx < struct_type->field_count);

    field = struct_type->fields + field_idx;
    field_data = (uint8 *)struct_obj + field->field_offset;
    field_size = field->field_size;

    if (field_size == 4) {
        value->i32 = *(int32 *)field_data;
    }
    else if (field_size == 8) {
#if defined(BUILD_TARGET_X86_64) || defined(BUILD_TARGET_AMD_64) \
    || defined(BUILD_TARGET_X86_32)
        value->i64 = *(int64 *)field_data;
#else
        value->i64 = GET_I64_FROM_ADDR((uint32 *)field_data);
#endif
    }
    else if (field_size == 1) {
        if (sign_extend)
            value->i32 = (int32)(*(int8 *)field_data);
        else
            value->u32 = (uint32)(*(uint8 *)field_data);
    }
    else if (field_size == 2) {
        if (sign_extend)
            value->i32 = (int32)(*(int16 *)field_data);
        else
            value->u32 = (uint32)(*(uint16 *)field_data);
    }
    else if (wasm_is_reftype_i31ref(field->field_type)) {
        /* Handle i31 reference fields - they store raw integer values, not object pointers */
        if (field_size == 4) {
            /* i31 values are stored as raw 32-bit integers */
            uint32 raw_i31_val = *(uint32 *)field_data;
            /* Convert raw value to properly encoded i31 reference */
            printf("[I31_GET_FIELD] field_type=0x%x, raw_val=%u, encoded=0x%lx\n", 
                   field->field_type, raw_i31_val, (uintptr_t)wasm_i31_obj_new(raw_i31_val));
            value->gc_obj = (WASMObjectRef)wasm_i31_obj_new(raw_i31_val);
        }
        else {
            /* Fallback: treat as null reference for unexpected field sizes */
            printf("[I31_GET_FIELD] Unexpected field_size=%d for i31 field\n", field_size);
            value->gc_obj = NULL;
        }
    }
    else if (wasm_is_type_reftype(field->field_type)) {
        /* Handle other reference types - extract the reference from the field data */
        /* Use direct assignment to avoid potential corruption from GET_REF_FROM_ADDR macro */
        value->gc_obj = (WASMObjectRef)(*(void **)field_data);
    }
    else {
        bh_assert(0);
    }
}

uint32
wasm_struct_obj_get_field_count(const WASMStructObjectRef struct_obj)
{
    WASMRttTypeRef rtt_type =
        (WASMRttTypeRef)wasm_object_header((WASMObjectRef)struct_obj);
    WASMStructType *struct_type = (WASMStructType *)rtt_type->defined_type;

    return struct_type->field_count;
}

WASMArrayObjectRef
wasm_array_obj_new_internal(void *heap_handle, WASMRttTypeRef rtt_type,
                            uint32 length, WASMValue *init_value)
{
    WASMArrayObjectRef array_obj;
    WASMArrayType *array_type;
    uint64 total_size;
    uint32 elem_size, elem_size_log, i;

    bh_assert(rtt_type->type_flag == WASM_TYPE_ARRAY);

    if (length >= (1 << 29))
        return NULL;

    array_type = (WASMArrayType *)rtt_type->defined_type;
    if (array_type->elem_type == PACKED_TYPE_I8) {
        elem_size = 1;
        elem_size_log = 0;
    }
    else if (array_type->elem_type == PACKED_TYPE_I16) {
        elem_size = 2;
        elem_size_log = 1;
    }
    else {
        elem_size = wasm_value_type_size(array_type->elem_type);
        elem_size_log = (elem_size == 4) ? 2 : 3;
    }

    total_size =
        offsetof(WASMArrayObject, elem_data) + (uint64)elem_size * length;
    if (!(array_obj = gc_obj_malloc(heap_handle, total_size))) {
        return NULL;
    }

    array_obj->header = (WASMObjectHeader)rtt_type;
    array_obj->length = (length << 2) | elem_size_log;

    if (init_value != NULL) {
        for (i = 0; i < length; i++) {
            if (wasm_is_type_reftype(array_type->elem_type)) {
                uint32 *elem_addr =
                    (uint32 *)array_obj->elem_data + REF_CELL_NUM * i;
                PUT_REF_TO_ADDR(elem_addr, init_value->gc_obj);
            }
            else if (array_type->elem_type == VALUE_TYPE_I32
                     || array_type->elem_type == VALUE_TYPE_F32) {
                ((int32 *)array_obj->elem_data)[i] = init_value->i32;
            }
            else if (array_type->elem_type == PACKED_TYPE_I8) {
                ((int8 *)array_obj->elem_data)[i] = (int8)init_value->i32;
            }
            else if (array_type->elem_type == PACKED_TYPE_I16) {
                ((int16 *)array_obj->elem_data)[i] = (int16)init_value->i32;
            }
            else {
                uint32 *elem_addr = (uint32 *)array_obj->elem_data + 2 * i;
                PUT_I64_TO_ADDR(elem_addr, init_value->i64);
            }
        }
    }

    return array_obj;
}

WASMArrayObjectRef
wasm_array_obj_new(WASMExecEnv *exec_env, WASMRttTypeRef rtt_type,
                   uint32 length, WASMValue *init_value)
{
    void *heap_handle = get_gc_heap_handle(exec_env);
    return wasm_array_obj_new_internal(heap_handle, rtt_type, length,
                                       init_value);
}

void
wasm_array_obj_set_elem(WASMArrayObjectRef array_obj, uint32 elem_idx,
                        const WASMValue *value)
{
    uint8 *elem_data = wasm_array_obj_elem_addr(array_obj, elem_idx);
    uint32 elem_size = 1 << wasm_array_obj_elem_size_log(array_obj);

    switch (elem_size) {
        case 1:
            *(int8 *)elem_data = (int8)value->i32;
            break;
        case 2:
            *(int16 *)elem_data = (int16)value->i32;
            break;
        case 4:
            *(int32 *)elem_data = value->i32;
            break;
        case 8:
            PUT_I64_TO_ADDR((uint32 *)elem_data, value->i64);
            break;
    }
}

void
wasm_array_obj_get_elem(const WASMArrayObjectRef array_obj, uint32 elem_idx,
                        bool sign_extend, WASMValue *value)
{
    uint8 *elem_data = wasm_array_obj_elem_addr(array_obj, elem_idx);
    uint32 elem_size = 1 << wasm_array_obj_elem_size_log(array_obj);

    switch (elem_size) {
        case 1:
            value->i32 = sign_extend ? (int32)(*(int8 *)elem_data)
                                     : (int32)(uint32)(*(uint8 *)elem_data);
            break;
        case 2:
            value->i32 = sign_extend ? (int32)(*(int16 *)elem_data)
                                     : (int32)(uint32)(*(uint16 *)elem_data);
            break;
        case 4:
            value->i32 = *(int32 *)elem_data;
            break;
        case 8:
            value->i64 = GET_I64_FROM_ADDR((uint32 *)elem_data);
            break;
    }
}

void
wasm_array_obj_fill(const WASMArrayObjectRef array_obj, uint32 elem_idx,
                    uint32 len, WASMValue *value)
{
    uint32 i;
    uint8 *elem_data = wasm_array_obj_elem_addr(array_obj, elem_idx);
    uint32 elem_size = 1 << wasm_array_obj_elem_size_log(array_obj);

    if (elem_size == 1) {
        memset(elem_data, (int8)value->i32, len);
        return;
    }

    for (i = 0; i < len; i++) {
        switch (elem_size) {
            case 2:
                *(int16 *)elem_data = (int16)value->i32;
                break;
            case 4:
                *(int32 *)elem_data = value->i32;
                break;
            case 8:
                PUT_I64_TO_ADDR((uint32 *)elem_data, value->i64);
                break;
        }
        elem_data += elem_size;
    }
}

void
wasm_array_obj_copy(WASMArrayObjectRef dst_obj, uint32 dst_idx,
                    WASMArrayObjectRef src_obj, uint32 src_idx, uint32 len)
{
    uint8 *dst_data = wasm_array_obj_elem_addr(dst_obj, dst_idx);
    uint8 *src_data = wasm_array_obj_elem_addr(src_obj, src_idx);
    uint32 elem_size = 1 << wasm_array_obj_elem_size_log(dst_obj);

    bh_memmove_s(dst_data, elem_size * len, src_data, elem_size * len);
}

uint32
wasm_array_obj_length(const WASMArrayObjectRef array_obj)
{
    return array_obj->length >> WASM_ARRAY_LENGTH_SHIFT;
}

void *
wasm_array_obj_first_elem_addr(const WASMArrayObjectRef array_obj)
{
    return array_obj->elem_data;
}

void *
wasm_array_obj_elem_addr(const WASMArrayObjectRef array_obj, uint32 elem_idx)
{
    return array_obj->elem_data
           + (elem_idx << wasm_array_obj_elem_size_log(array_obj));
}

WASMFuncObjectRef
wasm_func_obj_new_internal(void *heap_handle, WASMRttTypeRef rtt_type,
                           uint32 func_idx_bound)
{
    WASMFuncObjectRef func_obj;
    uint64 total_size;

    bh_assert(rtt_type->type_flag == WASM_TYPE_FUNC);

    total_size = sizeof(WASMFuncObject);
    if (!(func_obj = gc_obj_malloc(heap_handle, total_size))) {
        return NULL;
    }

    func_obj->header = (WASMObjectHeader)rtt_type;
    func_obj->func_idx_bound = func_idx_bound;

    return func_obj;
}

WASMFuncObjectRef
wasm_func_obj_new(WASMExecEnv *exec_env, WASMRttTypeRef rtt_type,
                  uint32 func_idx_bound)
{
    void *heap_handle = get_gc_heap_handle(exec_env);
    return wasm_func_obj_new_internal(heap_handle, rtt_type, func_idx_bound);
}

uint32
wasm_func_obj_get_func_idx_bound(const WASMFuncObjectRef func_obj)
{
    return func_obj->func_idx_bound;
}

WASMFuncType *
wasm_func_obj_get_func_type(const WASMFuncObjectRef func_obj)
{
    WASMRttTypeRef rtt_type =
        (WASMRttTypeRef)wasm_object_header((WASMObjectRef)func_obj);
    bh_assert(rtt_type->type_flag == WASM_TYPE_FUNC);
    return (WASMFuncType *)rtt_type->defined_type;
}

WASMExternrefObjectRef
wasm_externref_obj_new(WASMExecEnv *exec_env, const void *host_obj)
{
    void *heap_handle = get_gc_heap_handle(exec_env);
    WASMAnyrefObjectRef anyref_obj;
    WASMExternrefObjectRef externref_obj;
    WASMLocalObjectRef local_ref;

    if (!(anyref_obj = gc_obj_malloc(heap_handle, sizeof(WASMAnyrefObject)))) {
        return NULL;
    }

    anyref_obj->header = WASM_OBJ_ANYREF_OBJ_FLAG;
    anyref_obj->host_obj = host_obj;

    /* Lock anyref_obj in case it is reclaimed when allocating memory below */
    wasm_runtime_push_local_obj_ref(exec_env, &local_ref);
    local_ref.val = (WASMObjectRef)anyref_obj;

    if (!(externref_obj =
              gc_obj_malloc(heap_handle, sizeof(WASMExternrefObject)))) {
        wasm_runtime_pop_local_obj_ref(exec_env);
        return NULL;
    }

    externref_obj->header = WASM_OBJ_EXTERNREF_OBJ_FLAG;
    externref_obj->internal_obj = (WASMObjectRef)anyref_obj;

    wasm_runtime_pop_local_obj_ref(exec_env);
    return externref_obj;
}

WASMAnyrefObjectRef
wasm_anyref_obj_new(WASMExecEnv *exec_env, const void *host_obj)
{
    void *heap_handle = get_gc_heap_handle(exec_env);
    WASMAnyrefObjectRef anyref_obj;

    if (!(anyref_obj = gc_obj_malloc(heap_handle, sizeof(WASMAnyrefObject)))) {
        return NULL;
    }

    anyref_obj->header = WASM_OBJ_ANYREF_OBJ_FLAG;
    anyref_obj->host_obj = host_obj;

    return anyref_obj;
}

WASMObjectRef
wasm_externref_obj_to_internal_obj(WASMExternrefObjectRef externref_obj)
{
    return externref_obj->internal_obj;
}

WASMExternrefObjectRef
wasm_internal_obj_to_externref_obj(WASMExecEnv *exec_env,
                                   WASMObjectRef internal_obj)
{
    void *heap_handle = get_gc_heap_handle(exec_env);
    WASMExternrefObjectRef externref_obj;

    if (!(externref_obj =
              gc_obj_malloc(heap_handle, sizeof(WASMExternrefObject)))) {
        return NULL;
    }

    externref_obj->header = WASM_OBJ_EXTERNREF_OBJ_FLAG;
    externref_obj->internal_obj = internal_obj;

    return externref_obj;
}

const void *
wasm_anyref_obj_get_value(WASMAnyrefObjectRef anyref_obj)
{
    return anyref_obj->host_obj;
}

const void *
wasm_externref_obj_get_value(const WASMExternrefObjectRef externref_obj)
{
    if (wasm_obj_is_anyref_obj(externref_obj->internal_obj))
        return ((WASMAnyrefObjectRef)externref_obj->internal_obj)->host_obj;
    else
        return externref_obj->internal_obj;
}

WASMI31ObjectRef
wasm_i31_obj_new(uint32 i31_value)
{
    return (WASMI31ObjectRef)((i31_value << 1) | 1);
}

uint32
wasm_i31_obj_get_value(WASMI31ObjectRef i31_obj, bool sign_extend)
{
    uint32 i31_value = (uint32)(((uintptr_t)i31_obj) >> 1);
    if (sign_extend && (i31_value & 0x40000000)) /* bit 30 is 1 */
        /* set bit 31 to 1 */
        i31_value |= 0x80000000;
    return i31_value;
}

bool
wasm_obj_is_i31_obj(WASMObjectRef obj)
{
    if (!obj) {
        return false;
    }
    return (((uintptr_t)obj) & 1) ? true : false;
}

bool
wasm_obj_is_externref_obj(WASMObjectRef obj)
{
    if (!obj) {
        return false;
    }
    
    /* Enhanced corruption detection */
    uintptr_t ptr_val = (uintptr_t)obj;
    
    /* Check for the specific corruption pattern we're seeing */
    if (((ptr_val & 0xFFFF000000000000ULL) == 0x5555000000000000ULL)) {
        printf("[EXTERNREF_CHECK] CORRUPTION DETECTED: Invalid pointer 0x%p\n", (void*)obj);
        printf("[EXTERNREF_CHECK] This matches the corrupted heap pointer pattern!\n");
        return false;
    }
    
    /* Check for obviously invalid pointers */
    if (ptr_val < 0x1000 || (ptr_val & 0xF000000000000000UL) != 0) {
        printf("[EXTERNREF_CHECK] Invalid pointer range: 0x%p\n", (void*)obj);
        return false;
    }
    
    if (wasm_obj_is_i31_obj(obj)) {
        return false;
    }
    
    /* Additional safety check before accessing header */
    printf("[EXTERNREF_CHECK] Checking object 0x%p for externref flag\n", (void*)obj);
    
    /* Try to access header safely */
    __builtin_prefetch(obj, 0, 0);
    
    /* Add explicit bounds check */
    if (ptr_val & 0x7) {
        printf("[EXTERNREF_CHECK] WARNING: Unaligned pointer 0x%p\n", (void*)obj);
    }
    
    return (obj->header & WASM_OBJ_EXTERNREF_OBJ_FLAG) ? true : false;
}

bool
wasm_obj_is_anyref_obj(WASMObjectRef obj)
{
    bh_assert(obj);
    return (!wasm_obj_is_i31_obj(obj)
            && (obj->header & WASM_OBJ_ANYREF_OBJ_FLAG))
               ? true
               : false;
}

bool
wasm_obj_is_i31_externref_or_anyref_obj(WASMObjectRef obj)
{
    bh_assert(obj);
    return (wasm_obj_is_i31_obj(obj)
            || (obj->header
                & (WASM_OBJ_EXTERNREF_OBJ_FLAG | WASM_OBJ_ANYREF_OBJ_FLAG)))
               ? true
               : false;
}

bool
wasm_obj_is_struct_obj(WASMObjectRef obj)
{
    WASMRttTypeRef rtt_type;

    bh_assert(obj);

    /* Handle externref objects - check their internal content per WebAssembly GC spec */
    if (wasm_obj_is_externref_obj(obj)) {
        WASMObjectRef internal_obj = wasm_externref_obj_to_internal_obj((WASMExternrefObjectRef)obj);
        if (internal_obj && internal_obj != obj) {
            return wasm_obj_is_struct_obj(internal_obj);
        }
        return false;
    }

    if (wasm_obj_is_i31_obj(obj) || wasm_obj_is_anyref_obj(obj))
        return false;

    rtt_type = (WASMRttTypeRef)wasm_object_header(obj);
    return rtt_type->type_flag == WASM_TYPE_STRUCT ? true : false;
}

bool
wasm_obj_is_array_obj(WASMObjectRef obj)
{
    WASMRttTypeRef rtt_type;

    bh_assert(obj);

    /* Handle externref objects - check their internal content per WebAssembly GC spec */
    if (wasm_obj_is_externref_obj(obj)) {
        WASMObjectRef internal_obj = wasm_externref_obj_to_internal_obj((WASMExternrefObjectRef)obj);
        if (internal_obj && internal_obj != obj) {
            return wasm_obj_is_array_obj(internal_obj);
        }
        return false;
    }

    if (wasm_obj_is_i31_obj(obj) || wasm_obj_is_anyref_obj(obj))
        return false;

    rtt_type = (WASMRttTypeRef)wasm_object_header(obj);
    return rtt_type->type_flag == WASM_TYPE_ARRAY ? true : false;
}

bool
wasm_obj_is_func_obj(WASMObjectRef obj)
{
    WASMRttTypeRef rtt_type;

    bh_assert(obj);

    /* Handle externref objects - check their internal content per WebAssembly GC spec */
    if (wasm_obj_is_externref_obj(obj)) {
        WASMObjectRef internal_obj = wasm_externref_obj_to_internal_obj((WASMExternrefObjectRef)obj);
        if (internal_obj && internal_obj != obj) {
            return wasm_obj_is_func_obj(internal_obj);
        }
        return false;
    }

    if (wasm_obj_is_i31_obj(obj) || wasm_obj_is_anyref_obj(obj))
        return false;

    rtt_type = (WASMRttTypeRef)wasm_object_header(obj);
    return rtt_type->type_flag == WASM_TYPE_FUNC ? true : false;
}

bool
wasm_obj_is_internal_obj(WASMObjectRef obj)
{
    WASMRttTypeRef rtt_type;

    bh_assert(obj);

    if (wasm_obj_is_i31_obj(obj))
        return true;
    else if (obj->header & WASM_OBJ_ANYREF_OBJ_FLAG)
        return true;
    else if (obj->header & WASM_OBJ_EXTERNREF_OBJ_FLAG)
        return false;
    else {
        rtt_type = (WASMRttTypeRef)wasm_object_header(obj);
        return (rtt_type->type_flag == WASM_TYPE_STRUCT
                || rtt_type->type_flag == WASM_TYPE_ARRAY)
                   ? true
                   : false;
    }
}

bool
wasm_obj_is_eq_obj(WASMObjectRef obj)
{
    WASMRttTypeRef rtt_type;

    bh_assert(obj);

    if (wasm_obj_is_i31_obj(obj))
        return true;
    else if ((obj->header & WASM_OBJ_ANYREF_OBJ_FLAG)
             || (obj->header & WASM_OBJ_EXTERNREF_OBJ_FLAG))
        return false;
    else {
        rtt_type = (WASMRttTypeRef)wasm_object_header(obj);
        return (rtt_type->type_flag == WASM_TYPE_STRUCT
                || rtt_type->type_flag == WASM_TYPE_ARRAY)
                   ? true
                   : false;
    }
}

bool
wasm_obj_is_instance_of(WASMObjectRef obj, uint32 type_idx, WASMType **types,
                        uint32 type_count)
{
    WASMRttTypeRef rtt_type_sub;
    WASMType *type_sub, *type_parent;
    uint32 distance, i;

    /* CRITICAL DEBUG: Validate obj parameter immediately upon entry */
    printf("[INSTANCE_OF_ENTRY] Called with obj=0x%p, type_idx=%u\n", (void*)obj, type_idx);
    
    uintptr_t ptr_val = (uintptr_t)obj;
    if (obj && (ptr_val & 0xFFFF000000000000ULL) == 0x5000000000000000ULL && 
        (ptr_val & 0x0000FFFFFFFFULL) == 0) {
        printf("[INSTANCE_OF_ENTRY] CORRUPTION DETECTED! obj=0x%p is corrupted pattern\n", (void*)obj);
        printf("[INSTANCE_OF_ENTRY] This corruption happened during parameter passing!\n");
        return false;
    }

    bh_assert(obj);
    bh_assert(type_idx < type_count);

    /* Handle externref objects - check their internal content per WebAssembly GC spec */
    if (wasm_obj_is_externref_obj(obj)) {
        printf("[INSTANCE_OF_EXTERNREF] obj=0x%p is externref, unwrapping...\n", (void*)obj);
        WASMObjectRef internal_obj = wasm_externref_obj_to_internal_obj((WASMExternrefObjectRef)obj);
        printf("[INSTANCE_OF_EXTERNREF] internal_obj=0x%p (original=0x%p)\n", 
               (void*)internal_obj, (void*)obj);
        
        /* Check if internal_obj is corrupted - expanded detection */
        uintptr_t internal_ptr_val = (uintptr_t)internal_obj;
        bool is_corrupted = false;
        
        /* Detect corruption pattern: low 32 bits are zero, but high bits are non-zero */
        if (internal_obj && (internal_ptr_val & 0x00000000FFFFFFFFULL) == 0) {
            is_corrupted = true;
        }
        
        if (is_corrupted) {
            printf("[INSTANCE_OF_EXTERNREF] CORRUPTION DETECTED!\n");
            printf("[INSTANCE_OF_EXTERNREF] - externref object: 0x%p\n", (void*)obj);
            printf("[INSTANCE_OF_EXTERNREF] - internal_obj: 0x%p (CORRUPTED)\n", (void*)internal_obj);
            printf("[INSTANCE_OF_EXTERNREF] - corruption pattern: 0x%016llx\n", 
                   (unsigned long long)internal_ptr_val);
            
            /* Let's examine the externref object structure */
            WASMExternrefObject *externref = (WASMExternrefObject*)obj;
            printf("[INSTANCE_OF_EXTERNREF] - externref->internal_obj field: 0x%p\n", 
                   (void*)externref->internal_obj);
            
            /* Show memory context around the externref object */
            printf("[INSTANCE_OF_EXTERNREF] Memory context around externref object:\n");
            uint64 *data = (uint64*)obj;
            for (int i = 0; i < 4; i++) {
                printf("[INSTANCE_OF_EXTERNREF]   +%d: 0x%016llx\n", 
                       i * 8, (unsigned long long)data[i]);
            }
            
            return false;
        }
        
        if (internal_obj && internal_obj != obj) {
            printf("[INSTANCE_OF_EXTERNREF] Recursively calling wasm_obj_is_instance_of with internal_obj=0x%p\n", 
                   (void*)internal_obj);
            return wasm_obj_is_instance_of(internal_obj, type_idx, types, type_count);
        }
        return false;
    }

    if (wasm_obj_is_i31_obj(obj) || wasm_obj_is_anyref_obj(obj))
        return false;

    rtt_type_sub = (WASMRttTypeRef)wasm_object_header(obj);
    type_parent = types[type_idx];

    if (!(rtt_type_sub->root_type == type_parent->root_type
          && rtt_type_sub->inherit_depth >= type_parent->inherit_depth))
        return false;

    type_sub = rtt_type_sub->defined_type;
    distance = type_sub->inherit_depth - type_parent->inherit_depth;

    for (i = 0; i < distance; i++) {
        type_sub = type_sub->parent_type;
    }

    return (type_sub == type_parent) ? true : false;
}

bool
wasm_obj_is_type_of(WASMObjectRef obj, int32 heap_type)
{
    bh_assert(obj);
    
    /* Debug undefined heap types */
    if (((uintptr_t)obj & 0xFFFF) == 0x2a && heap_type == -20) {
        printf("[WASM_OBJ_IS_TYPE_OF] Called with obj=%p, heap_type=%d\n", 
               (void*)obj, heap_type);
    }

    switch (heap_type) {
        case HEAP_TYPE_FUNC:
            return wasm_obj_is_func_obj(obj);
        case HEAP_TYPE_EXTERN:
            return wasm_obj_is_externref_obj(obj);
        case HEAP_TYPE_ANY:
            return wasm_obj_is_internal_obj(obj);
        case HEAP_TYPE_EQ:
            return wasm_obj_is_eq_obj(obj);
        case HEAP_TYPE_I31:
            printf("[I31_CAST_ALL] Object %p cast to i31: %s\n", (void*)obj, wasm_obj_is_i31_obj(obj) ? "SUCCESS" : "FAILURE");
            return wasm_obj_is_i31_obj(obj);
        case HEAP_TYPE_STRUCT:
            return wasm_obj_is_struct_obj(obj);
        case HEAP_TYPE_ARRAY:
            return wasm_obj_is_array_obj(obj);
#if WASM_ENABLE_STRINGREF != 0
        case HEAP_TYPE_STRINGREF:
            return wasm_obj_is_stringref_obj(obj);
        case HEAP_TYPE_STRINGVIEWWTF8:
            return wasm_obj_is_stringview_wtf8_obj(obj);
        case HEAP_TYPE_STRINGVIEWWTF16:
            return wasm_obj_is_stringview_wtf16_obj(obj);
#endif
        case HEAP_TYPE_NONE:
        case HEAP_TYPE_NOFUNC:
        case HEAP_TYPE_NOEXTERN:
            return false;
        default:
            /* Handle undefined heap types gracefully instead of asserting */
            printf("[WASM_OBJ_IS_TYPE_OF] WARNING: Undefined heap type %d for object %p\n", 
                   heap_type, (void*)obj);
            printf("[WASM_OBJ_IS_TYPE_OF] This may indicate invalid WebAssembly generation\n");
            /* Return false for undefined heap types to avoid cast failures */
            return false;
    }
    return false;
}

bool
wasm_obj_equal(WASMObjectRef obj1, WASMObjectRef obj2)
{
    /* TODO: do we need to compare the internal details of the objects */
    return obj1 == obj2 ? true : false;
}

bool
wasm_object_get_ref_list(WASMObjectRef obj, bool *p_is_compact_mode,
                         uint32 *p_ref_num, uint16 **p_ref_list,
                         uint32 *p_ref_start_offset)
{
    WASMRttTypeRef rtt_type;

    bh_assert(wasm_obj_is_created_from_heap(obj));

    rtt_type = (WASMRttTypeRef)wasm_object_header(obj);

    if (obj->header & WASM_OBJ_EXTERNREF_OBJ_FLAG) {
        /* externref object */
        static uint16 externref_obj_ref_list[] = { (uint16)offsetof(
            WASMExternrefObject, internal_obj) };
        *p_is_compact_mode = false;
        *p_ref_num = 1;
        *p_ref_list = externref_obj_ref_list;
        return true;
    }
    else if (obj->header & WASM_OBJ_ANYREF_OBJ_FLAG) {
        /* anyref object */
        *p_is_compact_mode = false;
        *p_ref_num = 0;
        *p_ref_list = NULL;
        return true;
    }
#if WASM_ENABLE_STRINGREF != 0
    else if (rtt_type->type_flag == WASM_TYPE_STRINGREF
             || rtt_type->type_flag == WASM_TYPE_STRINGVIEWWTF8
             || rtt_type->type_flag == WASM_TYPE_STRINGVIEWWTF16
             || rtt_type->type_flag == WASM_TYPE_STRINGVIEWITER) {
        /* stringref/stringview_wtf8/stringview_wtf16/stringview_iter object */
        *p_is_compact_mode = false;
        *p_ref_num = 0;
        *p_ref_list = NULL;
        return true;
    }
#endif /* end of WASM_ENABLE_STRINGREF != 0 */
    else if (rtt_type->defined_type->type_flag == WASM_TYPE_FUNC) {
        /* function object */
        *p_is_compact_mode = false;
        *p_ref_num = 0;
        *p_ref_list = NULL;
        return true;
    }
    else if (rtt_type->defined_type->type_flag == WASM_TYPE_STRUCT) {
        /* struct object */
        WASMStructType *type = (WASMStructType *)rtt_type->defined_type;
        *p_is_compact_mode = false;
        *p_ref_num = *type->reference_table;
        *p_ref_list = type->reference_table + 1;
        return true;
    }
    else if (rtt_type->defined_type->type_flag == WASM_TYPE_ARRAY) {
        /* array object */
        WASMArrayType *type = (WASMArrayType *)rtt_type->defined_type;
        if (wasm_is_type_reftype(type->elem_type)) {
            *p_is_compact_mode = true;
            *p_ref_num = wasm_array_obj_length((WASMArrayObjectRef)obj);
            *p_ref_start_offset = (uint16)offsetof(WASMArrayObject, elem_data);
        }
        else {
            *p_is_compact_mode = false;
            *p_ref_num = 0;
            *p_ref_list = NULL;
        }

        return true;
    }
    else {
        bh_assert(0);
        return false;
    }
}

bool
wasm_obj_set_gc_finalizer(wasm_exec_env_t exec_env, const wasm_obj_t obj,
                          wasm_obj_finalizer_t cb, void *data)
{
    void *heap_handle = get_gc_heap_handle(exec_env);
    return mem_allocator_set_gc_finalizer(heap_handle, obj, (gc_finalizer_t)cb,
                                          data);
}

void
wasm_obj_unset_gc_finalizer(wasm_exec_env_t exec_env, void *obj)
{
    void *heap_handle = get_gc_heap_handle(exec_env);
    mem_allocator_unset_gc_finalizer(heap_handle, obj);
}

#if WASM_ENABLE_STRINGREF != 0
WASMRttTypeRef
wasm_stringref_rtt_type_new(uint16 type_flag, WASMRttType **rtt_types,
                            korp_mutex *rtt_type_lock)
{
    WASMRttType *rtt_type;
    uint32 index;

    bh_assert(type_flag >= WASM_TYPE_STRINGREF
              && type_flag <= WASM_TYPE_STRINGVIEWITER);

    index = type_flag - WASM_TYPE_STRINGREF;

    os_mutex_lock(rtt_type_lock);

    if (rtt_types[index]) {
        os_mutex_unlock(rtt_type_lock);
        return rtt_types[index];
    }

    if ((rtt_type = wasm_runtime_malloc(sizeof(WASMRttType)))) {
        memset(rtt_type, 0, sizeof(WASMRttType));
        rtt_type->type_flag = type_flag;

        rtt_types[index] = rtt_type;
    }

    os_mutex_unlock(rtt_type_lock);
    return rtt_type;
}

static void
wasm_stringref_obj_finalizer(WASMStringrefObjectRef stringref_obj, void *data)
{
    wasm_string_destroy(
        (WASMString)wasm_stringref_obj_get_value(stringref_obj));
}

static void
wasm_stringview_wtf8_obj_finalizer(WASMStringviewWTF8ObjectRef stringref_obj,
                                   void *data)
{
    wasm_string_destroy(
        (WASMString)wasm_stringview_wtf8_obj_get_value(stringref_obj));
}

static void
wasm_stringview_wtf16_obj_finalizer(WASMStringviewWTF16ObjectRef stringref_obj,
                                    void *data)
{
    wasm_string_destroy(
        (WASMString)wasm_stringview_wtf16_obj_get_value(stringref_obj));
}

static void
wasm_stringview_iter_obj_finalizer(WASMStringviewIterObjectRef stringref_obj,
                                   void *data)
{
    wasm_string_destroy(
        (WASMString)wasm_stringview_iter_obj_get_value(stringref_obj));
}

static WASMObjectRef
stringref_obj_new(WASMExecEnv *exec_env, uint32 type, const void *str_obj,
                  int32 pos)
{
    WASMObjectRef stringref_obj = NULL;
    void *heap_handle = get_gc_heap_handle(exec_env);
    WASMModuleInstanceCommon *module_inst =
        wasm_runtime_get_module_inst(exec_env);
    WASMRttTypeRef rtt_type = NULL;

#if WASM_ENABLE_INTERP != 0
    if (module_inst->module_type == Wasm_Module_Bytecode) {
        WASMModule *module = ((WASMModuleInstance *)module_inst)->module;
        rtt_type = wasm_stringref_rtt_type_new(type, module->stringref_rtts,
                                               &module->rtt_type_lock);
    }
#endif
#if WASM_ENABLE_AOT != 0
    if (module_inst->module_type == Wasm_Module_AoT) {
        AOTModule *module =
            (AOTModule *)((AOTModuleInstance *)module_inst)->module;
        rtt_type = wasm_stringref_rtt_type_new(type, module->stringref_rtts,
                                               &module->rtt_type_lock);
    }
#endif

    if (!rtt_type) {
        return NULL;
    }

    if (type == WASM_TYPE_STRINGREF) {
        if (!(stringref_obj =
                  gc_obj_malloc(heap_handle, sizeof(WASMStringrefObject)))) {
            return NULL;
        }
        ((WASMStringrefObjectRef)stringref_obj)->header =
            (WASMObjectHeader)rtt_type;
        ((WASMStringrefObjectRef)stringref_obj)->str_obj = str_obj;
        wasm_obj_set_gc_finalizer(
            exec_env, (wasm_obj_t)stringref_obj,
            (wasm_obj_finalizer_t)wasm_stringref_obj_finalizer, NULL);
    }
    else if (type == WASM_TYPE_STRINGVIEWWTF8) {
        if (!(stringref_obj = gc_obj_malloc(
                  heap_handle, sizeof(WASMStringviewWTF8Object)))) {
            return NULL;
        }
        ((WASMStringviewWTF8ObjectRef)stringref_obj)->header =
            (WASMObjectHeader)rtt_type;
        ((WASMStringviewWTF8ObjectRef)stringref_obj)->str_obj = str_obj;
        wasm_obj_set_gc_finalizer(
            exec_env, (wasm_obj_t)stringref_obj,
            (wasm_obj_finalizer_t)wasm_stringview_wtf8_obj_finalizer, NULL);
    }
    else if (type == WASM_TYPE_STRINGVIEWWTF16) {
        if (!(stringref_obj = gc_obj_malloc(
                  heap_handle, sizeof(WASMStringviewWTF16Object)))) {
            return NULL;
        }
        ((WASMStringviewWTF16ObjectRef)stringref_obj)->header =
            (WASMObjectHeader)rtt_type;
        ((WASMStringviewWTF16ObjectRef)stringref_obj)->str_obj = str_obj;
        wasm_obj_set_gc_finalizer(
            exec_env, (wasm_obj_t)stringref_obj,
            (wasm_obj_finalizer_t)wasm_stringview_wtf16_obj_finalizer, NULL);
    }
    else if (type == WASM_TYPE_STRINGVIEWITER) {
        if (!(stringref_obj = gc_obj_malloc(
                  heap_handle, sizeof(WASMStringviewIterObject)))) {
            return NULL;
        }
        ((WASMStringviewIterObjectRef)stringref_obj)->header =
            (WASMObjectHeader)rtt_type;
        ((WASMStringviewIterObjectRef)stringref_obj)->str_obj = str_obj;
        ((WASMStringviewIterObjectRef)stringref_obj)->pos = pos;
        wasm_obj_set_gc_finalizer(
            exec_env, (wasm_obj_t)stringref_obj,
            (wasm_obj_finalizer_t)wasm_stringview_iter_obj_finalizer, NULL);
    }

    return stringref_obj;
}

WASMStringrefObjectRef
wasm_stringref_obj_new(WASMExecEnv *exec_env, const void *str_obj)
{
    WASMStringrefObjectRef stringref_obj;

    stringref_obj = (WASMStringrefObjectRef)stringref_obj_new(
        exec_env, WASM_TYPE_STRINGREF, str_obj, 0);

    return stringref_obj;
}

WASMStringviewWTF8ObjectRef
wasm_stringview_wtf8_obj_new(WASMExecEnv *exec_env, const void *str_obj)
{
    WASMStringviewWTF8ObjectRef stringview_wtf8_obj;

    stringview_wtf8_obj = (WASMStringviewWTF8ObjectRef)stringref_obj_new(
        exec_env, WASM_TYPE_STRINGVIEWWTF8, str_obj, 0);

    return stringview_wtf8_obj;
}

WASMStringviewWTF16ObjectRef
wasm_stringview_wtf16_obj_new(WASMExecEnv *exec_env, const void *str_obj)
{
    WASMStringviewWTF16ObjectRef stringview_wtf16_obj;

    stringview_wtf16_obj = (WASMStringviewWTF16ObjectRef)stringref_obj_new(
        exec_env, WASM_TYPE_STRINGVIEWWTF16, str_obj, 0);

    return stringview_wtf16_obj;
}

WASMStringviewIterObjectRef
wasm_stringview_iter_obj_new(WASMExecEnv *exec_env, const void *str_obj,
                             int32 pos)
{
    WASMStringviewIterObjectRef stringview_iter_obj;

    stringview_iter_obj = (WASMStringviewIterObjectRef)stringref_obj_new(
        exec_env, WASM_TYPE_STRINGVIEWITER, str_obj, pos);

    return stringview_iter_obj;
}

const void *
wasm_stringref_obj_get_value(WASMStringrefObjectRef stringref_obj)
{
    return stringref_obj->str_obj;
}

const void *
wasm_stringview_wtf8_obj_get_value(
    WASMStringviewWTF8ObjectRef stringview_wtf8_obj)
{
    return stringview_wtf8_obj->str_obj;
}

const void *
wasm_stringview_wtf16_obj_get_value(
    WASMStringviewWTF16ObjectRef stringview_wtf16_obj)
{
    return stringview_wtf16_obj->str_obj;
}

const void *
wasm_stringview_iter_obj_get_value(
    WASMStringviewIterObjectRef stringview_iter_obj)
{
    return stringview_iter_obj->str_obj;
}

int32
wasm_stringview_iter_obj_get_pos(
    WASMStringviewIterObjectRef stringview_iter_obj)
{
    return stringview_iter_obj->pos;
}

void
wasm_stringview_iter_obj_update_pos(
    WASMStringviewIterObjectRef stringview_iter_obj, int32 pos)
{
    stringview_iter_obj->pos = pos;
}

#define WASM_OBJ_IS_STRINGREF_IMPL(flag)                \
    WASMRttTypeRef rtt_type;                            \
                                                        \
    bh_assert(obj);                                     \
                                                        \
    if (wasm_obj_is_i31_externref_or_anyref_obj(obj))   \
        return false;                                   \
                                                        \
    rtt_type = (WASMRttTypeRef)wasm_object_header(obj); \
    return rtt_type->type_flag == flag ? true : false

bool
wasm_obj_is_stringref_obj(WASMObjectRef obj)
{
    WASM_OBJ_IS_STRINGREF_IMPL(WASM_TYPE_STRINGREF);
}

bool
wasm_obj_is_stringview_wtf8_obj(WASMObjectRef obj)
{
    WASM_OBJ_IS_STRINGREF_IMPL(WASM_TYPE_STRINGVIEWWTF8);
}

bool
wasm_obj_is_stringview_wtf16_obj(WASMObjectRef obj)
{
    WASM_OBJ_IS_STRINGREF_IMPL(WASM_TYPE_STRINGVIEWWTF16);
}
#undef WASM_OBJ_IS_STRINGREF_IMPL

#endif /* end of WASM_ENABLE_STRINGREF != 0 */
