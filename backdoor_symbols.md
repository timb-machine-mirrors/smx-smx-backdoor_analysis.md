- `Llzma_delta_props_decoder` -> `backdoor_ctx_save`

- `Llzma_block_param_encoder_0` -> `backdoor_init`
- `Llzma_delta_props_encoder` -> `backdoor_init_stage2`

- `Llzma_simple_props_size_part_0` -> `is_gnu_relro`
- `Llzip_decode_1` -> `table1`
- `Lcrc64_clmul_1` -> `table2`	

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