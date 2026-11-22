#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""隐藏层「计时侧信道」加固 —— 信号 D：attr/current 写路径等时化。

App 侧用一对等长的写入探针测 /proc/self/attr/current 的失败延迟：

    A = "u:object_r:<不存在的类型>:s0"     -> 解析到 type 字段失败
    B = "<换行>u:object_r:<合法类型>:s0"   -> 首字节是换行

两者都必须返回 -EINVAL，但原生内核走的路径不同：

  * B 在 my_setprocattr() 的 if (size && str[0] && str[0] != '\n') 处被短路，
    直接落到 prepare_creds()/abort_creds() 的失败出口；A 则在
    string_to_context_struct() 内部失败并提前 return。一次 cred 分配/释放的
    差值（百纳秒量级）稳定地落在 A 与 B 之间。
  * 解析函数在第一个非法字段上就 goto out，失败深度直接变成耗时：畸形落在
    user 字段与落在 type 字段，成本不同。

本补丁把两条失败路径拉平，都终止在解析层、都付相同的字段查找次数：

  1. my_setprocattr()：换行开头的输入不再短路，同样进入
     security_context_to_sid_live()。返回码仍是 -EINVAL，语义不变。
  2. backup_string_to_context_struct()：user/role/type 三字段一律查完再判失败。
  3. string_to_context_struct()：同样三字段恒查，并把 backup(orig) 策略的字段
     查询推迟到 live 三字段全部通过之后 —— live 失败时 orig 结果本就被丢弃，
     推迟不改变任何可观察行为，却让畸形 context 不再为每个字段多付一次查找。

所有改动只落在失败路径，合法 context 的行为与耗时完全不变。

用法: patch_d.py <path/to/selinux_hide.c>
"""

import sys

MARK = "侧信道加固（信号 D）"

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

if len(sys.argv) != 2:
    sys.exit("用法: patch_d.py <path/to/selinux_hide.c>")

src = sys.argv[1]
with open(src, encoding="utf-8", errors="surrogateescape") as f:
    text = f.read()

if MARK in text:
    print("信号 D 已应用，跳过")
    sys.exit(0)

def rep(old, new, tag):
    global text
    n = text.count(old)
    if n != 1:
        raise SystemExit("[%s] 锚点出现 %d 次（预期 1）" % (tag, n))
    text = text.replace(old, new, 1)
    print("  ok:", tag)

# ---- 1. my_setprocattr：换行前缀不再短路，与非法 context 同走解析层 ----
rep(
"""    if (size && str[0] && str[0] != '\\n') {
        if (str[size - 1] == '\\n') {
            str[size - 1] = 0;
            size--;
        }""",
"""    /*
     * 侧信道加固（信号 D）：原生内核在 str[0] == '\\n' 时跳过整段解析，直接落到
     * prepare_creds()/abort_creds() 的失败出口；而非法 context 在解析内部就返回。
     * 两条失败路径的工作量不同，成对计时可测出固定差值。这里让换行开头的输入同样
     * 进入解析（返回码仍是 -EINVAL，语义不变），使两条失败路径都终止在解析层。
     */
    if (size && str[0]) {
        if (str[0] != '\\n' && str[size - 1] == '\\n') {
            str[size - 1] = 0;
            size--;
        }""",
    "D1 my_setprocattr newline short-circuit")

# ---- 2. string_to_context_struct：局部变量 ----
rep(
"""    char *scontextp, *p, oldc;
    bool orig_valid = true;""",
"""    char *scontextp, *p, oldc;
    char *user_str = NULL, *role_str = NULL, *type_str = NULL;
    bool orig_valid = true;""",
    "D2 local field pointers")

# ---- 3. user 段：延迟 backup 查询 ----
rep(
"""    usrdatum = symtab_search(&pol->p_users, scontextp);
    // Match native early return for an unknown user
    // Scanning later fields would add time based on their length
    if (!usrdatum)
        goto out;
    ctx->user = usrdatum->value;

    orig_usrdatum = symtab_search(&orig_pol->p_users, scontextp);
    if (orig_usrdatum)
        orig_ctx->user = orig_usrdatum->value;
    else
        orig_valid = false;""",
"""    user_str = scontextp;
    /*
     * 侧信道加固（信号 D）：字段查找一律走完再判失败，backup 策略的查询推迟到
     * live 三字段全部通过之后。原生内核在第一个非法字段上就返回，失败深度直接
     * 反映成耗时；若对每个字段都先查一次 orig symtab，畸形 context 又会比原生
     * 多付固定次数的哈希查找。推迟既不改变 live 失败时被丢弃的 orig 结果，也
     * 保持 live 成功时的查询结果完全不变。
     */
    usrdatum = symtab_search(&pol->p_users, scontextp);
    if (usrdatum)
        ctx->user = usrdatum->value;""",
    "D3 user field defer")

# ---- 4. role 段 ----
rep(
"""    role = symtab_search(&pol->p_roles, scontextp);
    // Match native early return for an unknown role before scanning type
    if (!role)
        goto out;
    ctx->role = role->value;

    orig_role = symtab_search(&orig_pol->p_roles, scontextp);
    if (orig_role)
        orig_ctx->role = orig_role->value;
    else
        orig_valid = false;""",
"""    role_str = scontextp;
    role = symtab_search(&pol->p_roles, scontextp);
    if (role)
        ctx->role = role->value;""",
    "D4 role field defer")

# ---- 5. type 段：三字段齐备后再查 backup ----
rep(
"""    typdatum = symtab_search(&pol->p_types, scontextp);
    if (!typdatum || typdatum->attribute) {
        live_valid = false;
    } else {
        ctx->type = typdatum->value;
        // Type values stay stable when KSU copies the live policy
        type_is_original = ksu_type_is_original(orig_pol, policy_generation, typdatum->value);
        if (type_is_original < 0) {
            orig_typdatum = symtab_search(&orig_pol->p_types, scontextp);
            if (orig_typdatum && !orig_typdatum->attribute)
                orig_ctx->type = orig_typdatum->value;
            else
                orig_valid = false;
        } else if (type_is_original) {
            orig_ctx->type = typdatum->value;
        } else {
            orig_valid = false;
        }
    }

    if (!live_valid)
        goto out;""",
"""    type_str = scontextp;
    typdatum = symtab_search(&pol->p_types, scontextp);
    if (!typdatum || typdatum->attribute)
        live_valid = false;
    else
        ctx->type = typdatum->value;

    /* 信号 D：live 三字段全部通过，此时才触碰 backup 策略。 */
    if (!usrdatum || !role || !live_valid)
        goto out;

    orig_usrdatum = symtab_search(&orig_pol->p_users, user_str);
    if (orig_usrdatum)
        orig_ctx->user = orig_usrdatum->value;
    else
        orig_valid = false;

    orig_role = symtab_search(&orig_pol->p_roles, role_str);
    if (orig_role)
        orig_ctx->role = orig_role->value;
    else
        orig_valid = false;

    // Type values stay stable when KSU copies the live policy
    type_is_original = ksu_type_is_original(orig_pol, policy_generation, typdatum->value);
    if (type_is_original < 0) {
        orig_typdatum = symtab_search(&orig_pol->p_types, type_str);
        if (orig_typdatum && !orig_typdatum->attribute)
            orig_ctx->type = orig_typdatum->value;
        else
            orig_valid = false;
    } else if (type_is_original) {
        orig_ctx->type = typdatum->value;
    } else {
        orig_valid = false;
    }""",
    "D5 type field defer + backup lookup")

# ---- 6. backup_string_to_context_struct：constant-work 三字段 ----
rep(
"""    usrdatum = symtab_search(&pol->p_users, scontextp);
    if (!usrdatum)
        goto out;

    ctx->user = usrdatum->value;""",
"""    /*
     * 侧信道加固（信号 D）：三个字段一律查完再判失败，使失败成本与首次失败的
     * 字段位置无关。原生内核在第一个非法字段上返回，不同畸形的 context 因此有
     * 不同的耗时，成对计时即可区分。
     */
    usrdatum = symtab_search(&pol->p_users, scontextp);
    if (usrdatum)
        ctx->user = usrdatum->value;""",
    "D6 backup user constant-work")

rep(
"""    role = symtab_search(&pol->p_roles, scontextp);
    if (!role)
        goto out;
    ctx->role = role->value;""",
"""    role = symtab_search(&pol->p_roles, scontextp);
    if (role)
        ctx->role = role->value;""",
    "D7 backup role constant-work")

rep(
"""    // ksu types fail like unknown types
    typdatum = symtab_search(&pol->p_types, scontextp);
    if (!typdatum || typdatum->attribute)
        goto out;

    type_is_original = ksu_type_is_original(live_pol, policy_generation, typdatum->value);""",
"""    // ksu types fail like unknown types
    typdatum = symtab_search(&pol->p_types, scontextp);
    if (typdatum && typdatum->attribute)
        typdatum = NULL;

    if (!usrdatum || !role || !typdatum)
        goto out;

    ctx->type = typdatum->value;

    type_is_original = ksu_type_is_original(live_pol, policy_generation, typdatum->value);""",
    "D8 backup type constant-work")

with open(src, "w", encoding="utf-8", errors="surrogateescape") as f:
    f.write(text)

print("信号 D 已写入: %s" % src)
