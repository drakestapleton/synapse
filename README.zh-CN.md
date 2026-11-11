<!-- languages -->
[English](README.md) · **简体中文**
<!-- /languages -->

<!-- github-native-navigation -->
[源码](https://github.com/aien-dev/synapse) · [逐步讲解](TEACHING.md) · [重放凭证](TEACHING-REPLAY.txt) · [议题](https://github.com/aien-dev/synapse/issues)
<!-- /github-native-navigation -->

# Synapse

Synapse 是 AIEN 的高吞吐、智能体原生的变更集与集成服务，提供确定性的 Git 对象物化和 Radicle 规范性验证（[aien-dev/aien-sovereign-core-mv#515](https://github.com/aien-dev/aien-sovereign-core-mv/issues/515)）。

**方向（2026-10-14）：** Synapse 正在成为面向 AI 的新一代 Git：一套只为 AI 智能体服务的源代码管理系统，汲取各类系统中最好的设计思想构建而成，同时保留 Git 作为一座小型的机器桥梁，用于导入、导出和对接现有工具（[ADR 0002](docs/adr/0002-synapse-first-git-as-bridge.md)，在 [aien-dev/synapse#8](https://github.com/aien-dev/synapse/issues/8) 中跟踪）。

## 我是如何构建它的：一个可以复现的小结果

我跟踪一个变更集，从递交和 WAL 持久化，一直走到免检出的树和标准 Git 对象。[完整讲解的课程](TEACHING.md)包含一次对损坏对象的拒绝；[最新的重放记录](docs/teaching-replay-2026-11-05.txt)是一个主机测试夹具，与规范的 Radicle 晋升相互独立。

## 架构概览

Synapse 加速高频的多智能体内循环（创建变更集、无需检出工作树即可检查虚拟树和差异、附加测试证据、检测冲突以及集成排队），同时强制守住三条不容妥协的边界：

1. **Git 兼容性**：被接受的变更集以确定性的方式物化为标准 Git `blob`、`tree` 和 `commit` 对象，与 `git fsck`、`git clone` 和 `git fetch` 兼容。
2. **面向人类的 GitHub 投影**：面向人类评审的投影（`GitHubPullRequestProjection`）只发布简洁的摘要和证据摘要值，不上传庞大的机器日志，也不会悄悄强制移动人类的分支。
3. **Radicle 规范权威**：快速的 WAL 摄入顺序（`WalSeq`）和 GitHub PR 状态都不会授予推进规范分支的权限。规范晋升（`RadicleCanonicalHead`）要求依据仓库的委托人法定人数阈值，对 `refs/rad/id` 和 `refs/namespaces/<nid>/refs/rad/sigrefs` 进行密码学验证。

## 工作区 crate

| Crate | 门禁 | 职责 |
| :--- | :--- | :--- |
| [`synapse-core`](crates/synapse-core) | 门禁 0 | 互不混用的标识类型（`ChangesetId`、`BlobDigest`、`GitOid`、`RadicleCanonicalHead`、`GitHubPullRequestProjection`、`IdempotencyKey`、`WalSeq`）、`ChangesetEnvelope` v1、`did:key` Ed25519 验证，以及 `RefusalCode` 分类体系 |
| [`synapse-store`](crates/synapse-store) | 门禁 1 | 单写者、仅追加的 WAL（`SWAL` v1），带 CRC32C 和 SHA-256 哈希链；可配置的 `fsync` 策略、内容寻址的 blob 存储、检查点压缩、GC、崩溃故障注入，以及 R1 原始块存储及其签名修复工具（`synapse-bench store-repair`，[规格说明](docs/R1_RAW_BLOCK_STORE.md#41-repair-after-a-checkpointcorrupt-refusal-issue-105)） |
| [`synapse-auth`](crates/synapse-auth) | 门禁 2 | Ed25519 能力授权（`Read`、`Propose`、`Evaluate`、`Review`、`Publish`）、过期与重放防护、速率与大小配额，以及哈希链式的安全审计日志 |
| [`synapse-api`](crates/synapse-api) | 门禁 2 | 有界的分页 API（`submit`、`get`、`diff`、`tree`、`history`、`provenance`、`conflicts`、`status`、`watch`）、免检出的虚拟树叠加层，以及精确的路径索引失效 |
| [`synapse-git`](crates/synapse-git) | 门禁 3 | 确定性的 Git 松散对象写入器与读取器、双向的 `ChangesetId <-> GitOid` 映射、ref 命名空间隔离，以及 GitHub PR 投影构建器 |
| [`synapse-radicle`](crates/synapse-radicle) | 门禁 3 | Radicle `refs/rad/id` 和 `refs/rad/sigrefs` 的 Ed25519 委托人阈值验证器，以及脑裂拒绝引擎 |
| [`synapse-bench`](crates/synapse-bench) | 门禁 4 | 对比鉴定测试框架（将 Synapse 摄入和免检出查询，与 Git 工作树和 Git 底层命令工作流进行对比），外加 WAL、Git 物化和 Radicle 规范性的一致性测试套件 |

## 关联仓库

下面每个工具都是独立的仓库，其根目录的 `.crumb` 将 `aien-dev/synapse@099a980` 记为父仓库（`extensions.map.parent`）。它们协调在 aien-dev 各处工作的智能体；要修改它们，请到各自的仓库，而不是在这里。

* [`synapse-claims`](https://github.com/aien-dev/synapse-claims)：仅追加、哈希链式、Ed25519 签名的租约账本，覆盖仓库、分支、路径 glob、PR 以及外部目标。冲突的租约会被拒绝，以退出码 2 退出，并指明持有者。
* [`synapse-map`](https://github.com/aien-dev/synapse-map)：组织的仓库关系图；`where` 把任务路由到所属的仓库，`new` 搭建一个新的关联仓库，`check` 报告孤立仓库和用途重复的仓库。
* [`synapse-pulse`](https://github.com/aien-dev/synapse-pulse)：将账本与 GitHub（经由 gh 防护层，使用条件请求）以及在线的智能体会话进行对账，并发出一个 `COORD-DRIFT:` 看门狗告警。
* [`synapse-mcp`](https://github.com/aien-dev/synapse-mcp)：MCP stdio 服务器，替智能体执行上述 CLI。
* [`synapse-board`](https://github.com/aien-dev/synapse-board)：根据账本渲染面向人类的看板（Markdown 和一个仅限 tailnet 访问的页面）。

## 文档与证据

* [领域术语表（`CONTEXT.md`）](CONTEXT.md)
* [ADR 0001：Synapse 架构、所有权边界与兼容性不变量](docs/adr/0001-synapse-architecture-and-boundaries.md)
* [ADR 0002：Synapse 优先的 AI 智能体源代码管理，以 Git 作为桥梁](docs/adr/0002-synapse-first-git-as-bridge.md)
* [门禁 0 现实核查审计与可复现基线](docs/GATE0_REALITY_CHECK_AND_BASELINE.md)
* [威胁模型与能力权限矩阵](docs/THREAT_MODEL.md)
* [变更集模式、WAL 格式、一致性与 GC 规格说明](docs/SCHEMA_AND_CONSISTENCY.md)
* [门禁 0 实测基线凭证（`evidence/gate0-baseline/`）](evidence/gate0-baseline/baseline_report.json)
* [门禁 4 对比鉴定报告](docs/GATE4_QUALIFICATION.md)
* [门禁 4 鉴定证据（`evidence/gate4-qualification/`）](evidence/gate4-qualification/report.json)，可用 `scripts/run_gate4_qualification.sh` 复现
* [D1 合并层级 T1（`docs/D1_MERGE_TIER_T1.md`）](docs/D1_MERGE_TIER_T1.md)：单个文件的行级三方合并，已对照 `git merge-tree` 和 `git merge-file` 进行校验（[证据](evidence/d1-merge-tier-t1/)）
* [Spark 验证门禁（`docs/PIPELINE.md`）](docs/PIPELINE.md)：互操作脚本和门禁 4 脚本都遵循 `CARGO_TARGET_DIR`，因此 `SYNAPSE-CONFORMANCE` 在 Spark 上的运行方式与在普通检出中完全相同

## 许可

本项目采用 Apache License, Version 2.0（Apache-2.0）许可。

## 人类主导的智能体工程

开发遵循人类主导的智能体工程（HDAE）：由人类定义目标、架构、约束、验收标准和停止点；智能体在这些边界之内实现、执行检查、诊断故障并进行修订。主张、验收和发布决策的责任仍由人类评审承担。这种开发方法有别于 Synapse 智能体原生的运行时接口，也不会改变其规范晋升规则。

关于该方法的文档说明以及一个系统软件案例研究，参见 Gregory M. Kurtzer，[*Ginux: Building an Independent Kernel That Runs Linux Userspace through Human-Directed Agentic Engineering*（2026）](https://doi.org/10.5281/zenodo.23682548)。
