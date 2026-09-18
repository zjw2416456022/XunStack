# XunStack 开发约束

- 先读本文件，再按任务检查相关源码；只维护 README.md 与 AGENTS.md。不要新建 PRD / STATUS / IMPLEMENTATION / SECURITY / DESIGN-SYSTEM 等平行文档。
- 当前分支只导入 Alpha 的检测核心；不能声称完整应用、原型、服务或 Mac 安装包已经在仓库中。继续接入已有源码，不另起工程。
- 固定 Rust / Axum / Tokio / rusqlite、目标三个 crate；前端 React / TypeScript / Vite。原型导入后位于 design/preview.html。保留其双主题、布局、动效、键盘与减少动画能力，不套普通后台模板。
- 代码、测试和实际构建/运行结果是事实来源。现有实现仍可能有错，不能以编译成功当作安全验收，也不能删测试、改断言或用假接口制造通过。
- 初次解析允许 CI 生成真实锁文件，核验后提交；之后使用 --locked。不得手写伪造锁文件。CI 阶段和实际覆盖要讲清楚。
- 普通删除只进回收站，永久删除只接受已回收对象，每次后端重新验密、固定计划一次消费，批量 DELETE。恢复必须原子不覆盖，密码正确不能绕过对象、范围或保护限制。
- experimental-write 默认关闭。先在自建临时目录验证平台、权限、竞态与崩溃恢复；不触碰真实业务站点。能力不足时拒绝，不能退回按任意路径 rm、跨盘复制再删除或递归清理目录。
- 随机单管理员、密码、入口分别使用安全随机源。秘密、客户样本、生产配置和数据库禁止提交。
- AI 只在原型；生产不接模型、Key、Agent 或样本外发。完整 Shell / PTY / root / sudo 和主动漏洞探测未获确认，不擅自加入。精确版本匹配不等于完整漏洞扫描。
- 使用独立开发分支和 PR；不强推、不覆盖用户已有修改、不自动合并或发布，不改仓库可见性，不替用户选开源许可证。

## 当前核心检查

```sh
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

仅在用法、重要限制和安全边界变化时更新 README / AGENTS。测试记录由 CI 生成，回复说明实际改动、结果和未验证项，不额外维护进度表。
