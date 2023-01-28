/*
  CarpetFuzz - fuzz argv code
*/
#include "afl-fuzz.h"

#define FLIP_BIT(_ar, _b)                   \
  do {                                      \
                                            \
    u8 *_arf = (u8 *)(_ar);                 \
    u32 _bf = (_b);                         \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7)); \
                                            \
  } while (0)


inline void ez_ck_free(void *ptr)
{
    if(ptr != NULL) {
        free(ptr);
        ptr = NULL;
    }
}

// read argvs groups from list file
void init_argv_list(afl_state_t *afl, u8 *argv_list_path)
{
    struct argv_list **argvs_list;
    u32 argvs_num, i = 0, j = 0;
    char *tmp = (char *)calloc(MAX_ARGV_LINE_LEN, sizeof(char));
    char *token;
    const char split[2] = " ";

    FILE *fp = fopen(argv_list_path, "r");
    if (fp == NULL) PFATAL("Can't read argv list file : %s", argv_list_path);
    
    fscanf(fp, "%d", &argvs_num);
    // fgetc the \n char, only fscanf need to consider it
    fgetc(fp);

    // calloc for groups of argvs, what we called argvs_list
    argvs_list = (struct argv_list **)calloc(argvs_num, sizeof(struct argv_list *));
    for(i = 0; i < argvs_num; ++i) {
        j = 0;
        memset(tmp, 0, MAX_ARGV_LINE_LEN);
        fgets(tmp, MAX_ARGV_LINE_LEN, fp);
        argvs_list[i] = (struct argv_list *)calloc(1, sizeof(struct argv_list));
        argvs_list[i]->argv_buf = (char **)calloc(MAX_ARGV_WORD_NUM, sizeof(char *));
        
        // split one group of argvs to argv
        token = strtok(tmp, split);
        argvs_list[i]->argv_buf[0] = (char *)calloc(MAX_ARGV_WORD_LEN, sizeof(char));
        strcpy(argvs_list[i]->argv_buf[0], token);
        while(1) {
            ++j;
            token = strtok(NULL, split);
            if(token != NULL) {
                argvs_list[i]->argv_buf[j] = (char *)calloc(MAX_ARGV_WORD_LEN, sizeof(char));
                strcpy(argvs_list[i]->argv_buf[j], token);
            }
            else break;
        }
    }

    ez_ck_free(tmp);
    fclose(fp);

    // record in afl
    afl->argvs_num = argvs_num;
    afl->argvs_list = argvs_list;
}


void write_argvs_file(afl_state_t *afl, char **argv)
{
    unlink(afl->fsrv.argvs_file);
    s32 fd = open(afl->fsrv.argvs_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", afl->fsrv.argvs_file); }

    u32 i = 0;

    while(argv[i] != NULL) {
        // replace @@ with /tmp_dir/.cur_input*
        if(strstr(argv[i], "@@")) {
            ck_write(fd, afl->fsrv.out_file, strlen(afl->fsrv.out_file) + 1, afl->fsrv.argvs_file);
        }
        else {
            ck_write(fd, argv[i], strlen(argv[i]) + 1 , afl->fsrv.argvs_file);
        }
        ++i;
    }

    close(fd);
}


/* Would only execute once. Traverse argvs_list with fuzzing randomly chosen seed. */
void fuzz_one_with_argvs(afl_state_t *afl)
{
    u32 len, temp_len;
    u32 idx1, idx2, rand_queue_id, r_max, r;
    u8 *orig_in, *out_buf;
    u64 orig_hit_cnt, new_hit_cnt;
    struct queue_entry *cur_tc;

    #define MAX_HAVOC_ENTRY 64

    r_max = MAX_HAVOC_ENTRY + 1;

    afl->stage_name = "argv-traverse";
    afl->stage_short = "argv";
    // afl->stage_max = ARGV_STAGE_MAX;
    afl->stage_max = afl->queued_items;
    orig_hit_cnt = afl->queued_items + afl->saved_crashes;

    for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {
        // randomly choose a seed from queued_items
        rand_queue_id = rand_below(afl, afl->queued_items);
        cur_tc = afl->queue_buf[rand_queue_id];
        afl->cur_depth = afl->queue_cur->depth;

        len = (u32) cur_tc->len;
        orig_in = queue_testcase_get(afl, cur_tc);

        for (idx1 = 0; idx1 < afl->argvs_num; ++idx1) {
            // traverse argvs_list in order
            afl->argvs_idx = idx1;
            write_argvs_file(afl, afl->argvs_list[afl->argvs_idx]->argv_buf);

            // restore the selected seed buf and len
            out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
            if (unlikely(!out_buf)) { PFATAL("alloc"); }
            memcpy(out_buf, orig_in, len);
            temp_len = len;

            u32 use_stacking = 1 << (1 + rand_below(afl, afl->havoc_stack_pow2));
            for (idx2 = 0; idx2 < use_stacking; ++idx2) {
              switch (r = rand_below(afl, r_max)) {
                case 0 ... 3: {
                  /* Flip a single bit somewhere. Spooky! */

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " FLIP_BIT1");
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  FLIP_BIT(out_buf, rand_below(afl, temp_len << 3));
                  break;
                }

                case 4 ... 7: {
                  /* Set byte to interesting value. */

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING8");
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  out_buf[rand_below(afl, temp_len)] =
                      interesting_8[rand_below(afl, sizeof(interesting_8))];
                  break;
                }

                case 8 ... 9: {
                  /* Set word to interesting value, little endian. */

                  if (temp_len < 2) { break; }

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING16");
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) =
                      interesting_16[rand_below(afl,
                                                sizeof(interesting_16) >> 1)];

                  break;
                }

                case 10 ... 11: {
                  /* Set word to interesting value, big endian. */

                  if (temp_len < 2) { break; }

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING16BE");
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) =
                      SWAP16(interesting_16[rand_below(
                          afl, sizeof(interesting_16) >> 1)]);

                  break;
                }

                case 12 ... 13: {
                  /* Set dword to interesting value, little endian. */

                  if (temp_len < 4) { break; }

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING32");
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) =
                      interesting_32[rand_below(afl,
                                                sizeof(interesting_32) >> 2)];

                  break;
                }

                case 14 ... 15: {
                  /* Set dword to interesting value, big endian. */

                  if (temp_len < 4) { break; }

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING32BE");
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) =
                      SWAP32(interesting_32[rand_below(
                          afl, sizeof(interesting_32) >> 2)]);

                  break;
                }

                case 16 ... 19: {
                  /* Randomly subtract from byte. */

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH8_");
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  out_buf[rand_below(afl, temp_len)] -=
                      1 + rand_below(afl, ARITH_MAX);
                  break;
                }

                case 20 ... 23: {
                  /* Randomly add to byte. */

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH8+");
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  out_buf[rand_below(afl, temp_len)] +=
                      1 + rand_below(afl, ARITH_MAX);
                  break;
                }

                case 24 ... 25: {
                  /* Randomly subtract from word, little endian. */

                  if (temp_len < 2) { break; }

                  u32 pos = rand_below(afl, temp_len - 1);

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16_-%u", pos);
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  *(u16 *)(out_buf + pos) -= 1 + rand_below(afl, ARITH_MAX);

                  break;
                }

                case 26 ... 27: {
                  /* Randomly subtract from word, big endian. */

                  if (temp_len < 2) { break; }

                  u32 pos = rand_below(afl, temp_len - 1);
                  u16 num = 1 + rand_below(afl, ARITH_MAX);

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16_BE-%u_%u",
                           pos, num);
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  *(u16 *)(out_buf + pos) =
                      SWAP16(SWAP16(*(u16 *)(out_buf + pos)) - num);

                  break;
                }

                case 28 ... 29: {
                  /* Randomly add to word, little endian. */

                  if (temp_len < 2) { break; }

                  u32 pos = rand_below(afl, temp_len - 1);

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16+-%u", pos);
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  *(u16 *)(out_buf + pos) += 1 + rand_below(afl, ARITH_MAX);

                  break;
                }

                case 30 ... 31: {
                  /* Randomly add to word, big endian. */

                  if (temp_len < 2) { break; }

                  u32 pos = rand_below(afl, temp_len - 1);
                  u16 num = 1 + rand_below(afl, ARITH_MAX);

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16+BE-%u_%u",
                           pos, num);
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  *(u16 *)(out_buf + pos) =
                      SWAP16(SWAP16(*(u16 *)(out_buf + pos)) + num);

                  break;
                }

                case 32 ... 33: {
                  /* Randomly subtract from dword, little endian. */

                  if (temp_len < 4) { break; }

                  u32 pos = rand_below(afl, temp_len - 3);

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32_-%u", pos);
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  *(u32 *)(out_buf + pos) -= 1 + rand_below(afl, ARITH_MAX);

                  break;
                }

                case 34 ... 35: {
                  /* Randomly subtract from dword, big endian. */

                  if (temp_len < 4) { break; }

                  u32 pos = rand_below(afl, temp_len - 3);
                  u32 num = 1 + rand_below(afl, ARITH_MAX);

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32_BE-%u-%u",
                           pos, num);
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  *(u32 *)(out_buf + pos) =
                      SWAP32(SWAP32(*(u32 *)(out_buf + pos)) - num);

                  break;
                }

                case 36 ... 37: {
                  /* Randomly add to dword, little endian. */

                  if (temp_len < 4) { break; }

                  u32 pos = rand_below(afl, temp_len - 3);

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32+-%u", pos);
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  *(u32 *)(out_buf + pos) += 1 + rand_below(afl, ARITH_MAX);

                  break;
                }

                case 38 ... 39: {
                  /* Randomly add to dword, big endian. */

                  if (temp_len < 4) { break; }

                  u32 pos = rand_below(afl, temp_len - 3);
                  u32 num = 1 + rand_below(afl, ARITH_MAX);

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32+BE-%u-%u",
                           pos, num);
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  *(u32 *)(out_buf + pos) =
                      SWAP32(SWAP32(*(u32 *)(out_buf + pos)) + num);

                  break;
                }

                case 40 ... 43: {
                  /* Just set a random byte to a random value. Because,
                      why not. We use XOR with 1-255 to eliminate the
                      possibility of a no-op. */

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " RAND8");
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  out_buf[rand_below(afl, temp_len)] ^=
                      1 + rand_below(afl, 255);
                  break;
                }

                case 44 ... 46: {
                  if (temp_len + HAVOC_BLK_XL < MAX_FILE) {
                    /* Clone bytes. */

                    u32 clone_len = choose_block_len(afl, temp_len);
                    u32 clone_from = rand_below(afl, temp_len - clone_len + 1);
                    u32 clone_to = rand_below(afl, temp_len);

#ifdef INTROSPECTION
                    snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                             " CLONE-%s-%u-%u-%u", "clone", clone_from,
                             clone_to, clone_len);
                    strcat(afl->mutation, afl->m_tmp);
#endif
                    u8 *new_buf = afl_realloc(AFL_BUF_PARAM(out_scratch),
                                              temp_len + clone_len);
                    if (unlikely(!new_buf)) { PFATAL("alloc"); }

                    /* Head */

                    memcpy(new_buf, out_buf, clone_to);

                    /* Inserted part */

                    memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);

                    /* Tail */
                    memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                           temp_len - clone_to);

                    out_buf = new_buf;
                    afl_swap_bufs(AFL_BUF_PARAM(out),
                                  AFL_BUF_PARAM(out_scratch));
                    temp_len += clone_len;
                  }

                  break;
                }

                case 47: {
                  if (temp_len + HAVOC_BLK_XL < MAX_FILE) {
                    /* Insert a block of constant bytes (25%). */

                    u32 clone_len = choose_block_len(afl, HAVOC_BLK_XL);
                    u32 clone_to = rand_below(afl, temp_len);

#ifdef INTROSPECTION
                    snprintf(afl->m_tmp, sizeof(afl->m_tmp), " CLONE-%s-%u-%u",
                             "insert", clone_to, clone_len);
                    strcat(afl->mutation, afl->m_tmp);
#endif
                    u8 *new_buf = afl_realloc(AFL_BUF_PARAM(out_scratch),
                                              temp_len + clone_len);
                    if (unlikely(!new_buf)) { PFATAL("alloc"); }

                    /* Head */

                    memcpy(new_buf, out_buf, clone_to);

                    /* Inserted part */

                    memset(new_buf + clone_to,
                           rand_below(afl, 2)
                               ? rand_below(afl, 256)
                               : out_buf[rand_below(afl, temp_len)],
                           clone_len);

                    /* Tail */
                    memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                           temp_len - clone_to);

                    out_buf = new_buf;
                    afl_swap_bufs(AFL_BUF_PARAM(out),
                                  AFL_BUF_PARAM(out_scratch));
                    temp_len += clone_len;
                  }

                  break;
                }

                case 48 ... 50: {
                  /* Overwrite bytes with a randomly selected chunk bytes. */

                  if (temp_len < 2) { break; }

                  u32 copy_len = choose_block_len(afl, temp_len - 1);
                  u32 copy_from = rand_below(afl, temp_len - copy_len + 1);
                  u32 copy_to = rand_below(afl, temp_len - copy_len + 1);

                  if (likely(copy_from != copy_to)) {
#ifdef INTROSPECTION
                    snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                             " OVERWRITE_COPY-%u-%u-%u", copy_from, copy_to,
                             copy_len);
                    strcat(afl->mutation, afl->m_tmp);
#endif
                    memmove(out_buf + copy_to, out_buf + copy_from, copy_len);
                  }

                  break;
                }

                case 51: {
                  /* Overwrite bytes with fixed bytes. */

                  if (temp_len < 2) { break; }

                  u32 copy_len = choose_block_len(afl, temp_len - 1);
                  u32 copy_to = rand_below(afl, temp_len - copy_len + 1);

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                           " OVERWRITE_FIXED-%u-%u", copy_to, copy_len);
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  memset(out_buf + copy_to,
                         rand_below(afl, 2)
                             ? rand_below(afl, 256)
                             : out_buf[rand_below(afl, temp_len)],
                         copy_len);

                  break;
                }

                case 52: {
                  /* Increase byte by 1. */

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ADDBYTE_");
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  out_buf[rand_below(afl, temp_len)]++;
                  break;
                }

                case 53: {
                  /* Decrease byte by 1. */

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " SUBBYTE_");
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  out_buf[rand_below(afl, temp_len)]--;
                  break;
                }

                case 54: {
                  /* Flip byte. */

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " FLIP8_");
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  out_buf[rand_below(afl, temp_len)] ^= 0xff;
                  break;
                }

                case 55 ... 56: {
                  if (temp_len < 4) { break; }

                  /* Switch bytes. */

                  u32 to_end, switch_to, switch_len, switch_from;
                  switch_from = rand_below(afl, temp_len);
                  do {
                    switch_to = rand_below(afl, temp_len);

                  } while (switch_from == switch_to);

                  if (switch_from < switch_to) {
                    switch_len = switch_to - switch_from;
                    to_end = temp_len - switch_to;

                  } else {
                    switch_len = switch_from - switch_to;
                    to_end = temp_len - switch_from;
                  }

                  switch_len = choose_block_len(afl, MIN(switch_len, to_end));

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                           " SWITCH-%s-%u-%u-%u", "switch", switch_from,
                           switch_to, switch_len);
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  u8 *new_buf =
                      afl_realloc(AFL_BUF_PARAM(out_scratch), switch_len);
                  if (unlikely(!new_buf)) { PFATAL("alloc"); }

                  /* Backup */

                  memcpy(new_buf, out_buf + switch_from, switch_len);

                  /* Switch 1 */

                  memcpy(out_buf + switch_from, out_buf + switch_to,
                         switch_len);

                  /* Switch 2 */

                  memcpy(out_buf + switch_to, new_buf, switch_len);

                  break;
                }

                // MAX_HAVOC_ENTRY = 64
                case 57 ... MAX_HAVOC_ENTRY: {
                  /* Delete bytes. */

                  if (temp_len < 2) { break; }

                  /* Don't delete too much. */

                  u32 del_len = choose_block_len(afl, temp_len - 1);
                  u32 del_from = rand_below(afl, temp_len - del_len + 1);

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp), " DEL-%u-%u",
                           del_from, del_len);
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  memmove(out_buf + del_from, out_buf + del_from + del_len,
                          temp_len - del_from - del_len);

                  temp_len -= del_len;

                  break;
                }
              }
            }

            common_fuzz_stuff(afl, out_buf, temp_len);
        }

        // cur_tc->skip_fuzz_one = true;

        show_stats(afl);
        if (unlikely(afl->stop_soon)) break;
    }

    new_hit_cnt = afl->queued_items + afl->saved_crashes;
    afl->stage_finds[STAGE_ARGV] += new_hit_cnt - orig_hit_cnt;
    afl->stage_cycles[STAGE_ARGV] += afl->stage_max;
    
}