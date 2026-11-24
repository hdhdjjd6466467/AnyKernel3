# 修复进度（PROGRESS）

> 本文件记录本仓库当前改到哪一步、验证到哪一步、还差什么。改代码前先看这里，改完同步更新。

## 0. 当前基线

| 项 | 值 |
|---|---|
| 分支 | `build-3k`（与 `main` 同一提交） |
| 最新提交 | `d479468` 功能默认开启：ZRAM / BBG / 网络增强 / CVE-2026-43499 |
| 目标内核 | 5.10.236-android12 / 5.15.78-android13 / 6.6.118-android15 |
| 变体 | SukiSU-Nova（侧信道补丁只对它生效） |

## 1. 已完成的修改（按提交顺序）

| 提交 | 内容 | 文件 |
|---|---|---|
| `caa513a` | 侧信道信号 A：`rules.c` 元数据发布挪到 `rcu_assign_pointer()` 之后；信号 B：`selinux_hide.c` backup 解析加 `!rc`；信号 C：`newfstatat/faccessat` 门控上提到 tracepoint；D 保持不动（上游 #3981 已对齐） | `scripts/sidechan_hide/{apply.sh,README.md}`、`.github/workflows/build.yml` |
| `2f67df3` | `avd.seqno` 归一化：`sel_write_access()` 回复第 5 字段恒为 0（Duck Detector SELinux 卡片唯一 DANGER 判据） | `scripts/avdseqno_fix/apply.sh`、`build.yml` |
| `9569f25` | 信号 A 改为按调用点重定位（`ksu_set_original_types(...)` / `ksu_advance_original_types(...)` → 其后最近的 `rcu_assign_pointer`），不再依赖函数名/签名；补回被误删的 `RULES_FILE` | `scripts/sidechan_hide/apply.sh` |
| `402e4e8` | HWID 绑定默认关闭 | `build.yml` |
| `8a1dc19` | 恢复被截断的 `build.yml`（112KB→51KB 事故）并重新接线 `ak3_name_prefix` | `build.yml` |
| `c4a8fb4` | 5.10 适配一加：`a12-5-10` / `a13-5-10` 的 `supp_op` 改 true | `kernel-a12-5-10.yml`、`kernel-a13-5-10.yml` |
| `d479468` | `use_zram` / `use_bbg` / `use_net_enhance` / `cve_2026_43499_patch` 默认全部 true；a16/a17 的硬编码 `use_zram: false` 改 true | 全部 workflow + `main.yml` |
| 待提交 | #3877 同源失败路径对齐：未知 user/role 早退 + attr/current 换行短路（对齐 tiann/KernelSU #3877 = KernelSU-Next v3.4.2 #1601） | `scripts/sidechan_3877/apply.sh`、`build.yml` |

另有一个被取代的中间提交 `329ccb4`（补丁失败即跳过），已被 `9569f25` 替换，不要再回退到那个行为。

## 2. 新增能力

- **OnePlus 专用工作流** `.github/workflows/kernel-op-a15-6-6.yml`：`supp_op` 固定 true，AK3 产物名带 `OnePlus-` 前缀（靠 `build.yml` 新增的 `ak3_name_prefix` 输入）。
- **一加支持默认开启**：`build.yml`、`kernel-a15-6-6`、`kernel-a16-6-12`、`kernel-custom` 的 `supp_op` 默认 true；5.10 两条（a12/a13-5-10）同样打开。
- **AK3 命名前缀**：`ak3_name_prefix` 默认空，不影响既有产物名。

## 3. 验证证据

| 项 | 结论 | 证据 |
|---|---|---|
| 信号 A（顺序） | **已在真实 SukiSU-Nova 源码生效** | 5.10.236 构建日志 07:37:14：`rules.c: original-types 元数据已改为随策略指针发布` / `信号 A 已修复` |
| 信号 A（原子） | **已生效** | 同一条日志：`sepolicy.c: limit/generation 已合并为单次原子发布` |
| 信号 B / C | 已生效 | 同一条日志：`backup 解析已加 !rc 守卫`、`allow-uid 门控` |
| `avd.seqno` 归一化 | 本地三版源码验证通过、幂等 | 5.10 / 5.15 / 6.6 的 `selinuxfs.c` 均命中，二次运行跳过 |
| 5.10 一加 + 四件套 | **构建中待确认** | run 45136518277 |
| 6.6 一加 + 四件套 | **构建中待确认** | run 45136523112 |

## 4. 待办 / 已知问题

- [ ] **恢复完整矩阵**：`build-3k` 上把 `kernel-a12-5-10` / `kernel-a13-5-15` / `kernel-a15-6-6` 的 matrix 裁成单条（236 / 78 / 118），`main` 快进后也继承了裁剪。验证完需要把三条工作流的完整 `include` 列表补回。
- [ ] **`.gitattributes` 加 `*.yml text eol=lf`**：PowerShell 重写导致 CRLF→LF 整文件差异（最近一次提交 1049/1049 行就是这样）。
- [ ] **5.15 / 6.1 是否也要一加支持**：目前 `supp_op` 仍 false，只开了 5.10 与 6.6/6.12。
- [ ] **avd.seqno 的 CI 侧确认**：本地产物已验证，等 5.10/6.6 构建产物上机复扫 Duck Detector。
- [ ] **信号 D（attr/current）**：明确不动。上游 #3981 已对齐 stock；自行“拉平”会与 stock 分叉。

## 5. 构建与触发

```bash
# 本地改动 → 推送
git push origin build-3k
git push origin build-3k:main        # 快进到 main，工作流才会注册/可见

# 触发（需要 GitHub token；或直接在 Actions 页面点 Run workflow）
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://api.github.com/repos/hdhdjjd6466467/AnyKernel3/actions/workflows/kernel-a12-5-10.yml/dispatches \
  -d '{"ref":"build-3k","inputs":{"kernelsu_variant":"SukiSU-Nova"}}'
```

当前三条目标内核的裁剪后入口：

| 目标 | 工作流 |
|---|---|
| 5.10.236-android12 | `kernel-a12-5-10.yml`（matrix 只剩 236） |
| 5.15.78-android13 | `kernel-a13-5-15.yml`（matrix 只剩 78） |
| 6.6.118-android15 | `kernel-a15-6-6.yml` 与 `kernel-op-a15-6-6.yml`（matrix 只剩 118） |

## 6. 关键实现位置

| 补丁 | 落点 | 判据 |
|---|---|---|
| 信号 A-顺序 | `kernel/selinux/rules.c` 两个发布点 | `KSU_SIDECHAN_A_PUBLISH` |
| 信号 A-原子 | `kernel/selinux/sepolicy.c` original-types 三函数 | `KSU_SIDECHAN_A_ATOMIC` |
| 信号 B | `kernel/feature/selinux_hide.c` | `KSU_SIDECHAN_B_GUARD` |
| 信号 C | `kernel/hook/syscall_hook_manager.c` | `KSU_SIDECHAN_C_GATE` |
| avd.seqno | `security/selinux/selinuxfs.c: sel_write_access()` | `KSU_AVDSEQNO_ZERO` |
| #3877-E 失败路径早退 | `kernel/feature/selinux_hide.c` `string_to_context_struct()` user/role 段 | `KSU_SIDECHAN_3877_FASTFAIL` |
| #3877-F 换行短路 | `kernel/feature/selinux_hide.c` `my_setprocattr()` | `KSU_SIDECHAN_3877_NEWLINE` |

以上标记都可在产物日志里 `grep` 到，用来判断补丁是真打上还是被跳过。
