# 巡栈 / XunStack

服务器与应用安全检测与处置工具。正式路线为 Rust 本机服务、React / TypeScript 浏览器界面和 SQLite。

> **当前不能部署完整应用，也没有可下载安装的 Mac / Linux 程序包。** 此分支只有已导入的 `xunstack-core` Rust 检测核心。下面的源码下载、编译和测试不是应用安装；测试成功不会启动网页，也不会生成管理员账号或 UI 访问地址。

[下载当前分支源码 ZIP](https://github.com/zjw2416456022/XunStack/archive/refs/heads/dev/source-alpha-ci.zip) · [查看 CI](https://github.com/zjw2416456022/XunStack/actions/workflows/core.yml) · [查看开发 PR](https://github.com/zjw2416456022/XunStack/pull/1) · [发布页（目前无应用包）](https://github.com/zjw2416456022/XunStack/releases)

## 下载什么、在哪里下载

| 你的目的 | 当前可获取的内容 | 能否直接运行 UI |
| --- | --- | --- |
| 查看代码、让 Codex 继续开发 | 当前分支的源码 ZIP，或用 Git 克隆 | 不能，尚无应用服务和正式前端 |
| Mac 本机部署验收 | 尚未提供 macOS 预编译应用包 | 不能 |
| Linux x86_64 / ARM64 部署 | 尚未提供 Linux 预编译应用包 | 不能 |
| 查看自动化测试 | Actions 中各平台的执行步骤与日志 | 不是应用包 |
| 不联网安装 | 尚未提供完整离线发行包 | 不能，仅有源码 ZIP 不足以离线安装 |

截至本次说明更新，仓库没有 Release，当前核心 CI 也没有上传可下载的应用 Artifact。不要把 `Code → Download ZIP`、以后发布页中自动生成的 `Source code (zip)` 或 `Source code (tar.gz)` 当作预编译安装包。GitHub 的这些下载是源码快照，参见[官方说明](https://docs.github.com/en/repositories/working-with-files/using-files/downloading-source-code-archives)。

### 方式一：浏览器下载源码

打开[开发分支](https://github.com/zjw2416456022/XunStack/tree/dev/source-alpha-ci)，确认左上角是 `dev/source-alpha-ci`，点击绿色 **Code → Download ZIP**；也可以使用本页顶部的源码 ZIP 链接。

解压后，进入包含 `Cargo.toml`、`README.md`、`AGENTS.md` 的目录。源码不按 CPU 分包，同一份源码用于各目标平台。当前 PR 尚未合并，下载 `main` 不会包含该开发分支的检测核心。

### 方式二：Git 克隆，适合继续开发

在准备存放项目的目录执行；目标 `XunStack` 目录应当尚不存在：

```sh
git clone --branch dev/source-alpha-ci --single-branch \
  https://github.com/zjw2416456022/XunStack.git XunStack
cd XunStack
git branch --show-current
git rev-parse HEAD
```

已克隆过的仓库先执行 `git status` 检查本地修改，不要覆盖未提交工作。确认工作区干净后再更新该分支：

```sh
git fetch origin
git switch dev/source-alpha-ci
git pull --ff-only origin dev/source-alpha-ci
```

分支下载会随提交更新；复现某次 CI 时，以该次运行记录中的提交为准。

## 在 Mac 上运行检测核心测试（开发用途，不是部署）

**只准备使用或验收 UI 的用户，现在不需要为了这个阶段安装 Rust、Node 或数据库。** 以下步骤供开发者检查当前核心源码。

需要 Git、Rust 工具链和系统编译/链接工具；当前核心不需要 Node、PHP、Java、Docker、MySQL 或独立 SQLite 服务。

先检查 Apple Command Line Tools：

```sh
xcode-select -p
```

仅当尚未安装时执行 `xcode-select --install`，完成系统安装窗口后再继续。Rust 官方提供[安装说明](https://doc.rust-lang.org/book/ch01-01-installation.html)和 [rustup 安装入口](https://rust-lang.org/tools/install/)。未安装 rustup 时，可以使用官方命令；不要加 `sudo`：

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
```

下载源码后，在包含 `Cargo.toml` 的项目根目录执行：

```sh
# rustup 根据仓库 rust-toolchain.toml 选择固定版本；首次使用需要联网下载。
rustup show active-toolchain
rustc --version
cargo --version

# 初次解析真实依赖锁；已有锁文件时保留，不重新解析。
if [ ! -f Cargo.lock ]; then
  cargo generate-lockfile
fi

cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

当前测试覆盖基线比较、文件风险规则、保护策略和本地公告匹配。成功退出只说明本次核心检查通过，不代表完整应用验收。仓库没有 `main.rs` 应用入口，不要执行 `cargo run`、`./xunstack serve`、`npm install` 或不存在的 `install.sh` 来尝试启动 UI。

目前 `Cargo.lock` 尚未纳入仓库，初次 CI 会真实解析依赖；该阶段不是可复现的正式发行构建。核验并提交锁文件后，构建和测试继续使用 `--locked`。首次工具链与依赖下载需要网络，不能把上述流程称为离线部署。

Linux 开发者同样使用上述核心检查命令，并根据系统安装 Git、GCC/Clang 与链接工具；Ubuntu 可使用 `build-essential`。麒麟、统信等环境应按实际发行版准备工具链，不直接套用其他发行版的安装命令。

## 平台与原生 CI

| 平台 | CI 运行器 | 运行时架构校验 | 当前测试范围 |
| --- | --- | --- | --- |
| Linux x86_64 | `ubuntu-24.04` | `x86_64` | Rust 检测核心 |
| Linux ARM64 | `ubuntu-24.04-arm` | `aarch64` | Rust 检测核心 |
| Mac Apple Silicon | `macos-15` | `arm64` | Rust 检测核心 |
| Mac Intel | `macos-15-intel` | `x86_64` | Rust 检测核心 |

以上使用原生运行器，不以交叉编译或 QEMU 代替。具体结果以 [Actions](https://github.com/zjw2416456022/XunStack/actions/workflows/core.yml) 为准；工作流定义在 `.github/workflows/core.yml`，官方运行器规格见 [GitHub 文档](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)。

进入一次运行，打开 `Core / Linux ARM64` 等任务，可查看架构校验、`cargo check`、Clippy 和实际单元测试日志。当前 workflow 不生成应用发行包；没有 Artifacts 区域不代表下载权限有问题。

Ubuntu ARM64 的核心检查不等于麒麟、统信或其他信创系统的应用实机验收。龙芯等其他架构仍是后续适配目标，不能仅凭同为 Linux 就认定通过。

## 应用部署与离线交付（尚未开放）

目标交付方式是：选择匹配操作系统和 CPU 的预编译应用包 → 校验 → 解压/安装 → 初始化随机单管理员与安全入口 → 启动后通过浏览器访问。运行端不要求现场编译 Rust 或前端。

包应按以下平台区分；**这是后续选包规则，不是已有下载项**：

| 安装目标 | 应选择的应用包类型 |
| --- | --- |
| Mac Apple Silicon | macOS ARM64 |
| Mac Intel | macOS x86_64 |
| Linux x86_64 | Linux x86_64，并核对发行版/链接库要求 |
| Linux ARM64 | Linux ARM64，并核对发行版/链接库要求 |

Mac ARM64 和 Linux ARM64 不能互用同一个二进制。服务应使用最小必要权限，不要求为验收默认以 root 运行。

目前没有应用二进制、安装脚本、服务启动入口或发布校验文件，因此这里不提供尚不能执行的安装命令，也不使用 `latest/download/...` 拼出不存在的包地址。

可部署交付必须同时包含：真实下载入口与架构说明、文件校验、经过测试的安装/启动/停止/卸载命令、随机凭据和 UI 地址说明、数据与回收站位置、升级保留与恢复流程。离线包还应包含运行所需的前端资源、基础规则及必要组件；漏洞库覆盖和更新时间需要明示，安装时不能再临时下载依赖或把未覆盖项显示为安全。

当前尚未完成 HTTP 服务、正式前端、SQLite 应用层、真实目录扫描、报告导出和安全回收站的入库与联调；原型也尚未放入此分支。这不是 README 漏一条启动命令就能解决的状态，不应在业务服务器上把当前源码当作完整应用验收。

## 已导入的核心能力与边界

- 风险、证据、文件身份和扫描覆盖数据模型；文件及少量静态配置规则；Laravel、Spring Boot / Cloud、BladeX 识别线索。
- 基于原始路径身份和完整哈希的基线比较；未覆盖路径不能直接报告为删除。
- 本地公告精确版本匹配，没有生产漏洞库，不是完整漏洞扫描器；保护策略、展示转义及 CSV 公式注入防护。

后续接入沿用已有 Alpha 源码与高级原型，不重建普通后台模板。普通删除必须先进入回收站；永久删除每次后端重新验密，只授权固定对象集合；恢复不得覆盖已有文件。未验证的文件写能力默认关闭，所有写测试只使用自建临时目录。

AI 只在原型体现；完整 Shell 和主动漏洞探测权限未确认，不自行开放。没有真实公告库或完整检测证据时显示未覆盖，不把文件启发式冒充 CVE。单管理员账号、密码和入口分别随机生成的要求尚待应用层实现；秘密、客户样本和生产数据库禁止提交。

## 维护

只维护 `README.md` 和 `AGENTS.md` 两份手写说明。原型导入后放 `design/preview.html`，只供视觉和交互参考，不要求随代码同步。代码、测试及实际运行结果是实现事实来源，测试记录由 CI 生成，不新增 PRD / STATUS / SECURITY 等平行文档。

当前没有选择项目开源许可证；保留 `publish=false`，不自动合并、部署、发布或修改仓库可见性。第三方许可与自动生成的测试材料不属于需要删除的说明文档。
