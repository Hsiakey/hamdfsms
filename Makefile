# Hamster ver.0.0.9 — Makefile
#
# 架构：hamsterd 统一守护进程（:9100 JSON 行协议 + 二进制长度前缀负载）
#       hamster_manager 网络层/启动器（:9102 Electron IPC）
#
# 用法:
#   mingw32-make                编译全部
#   mingw32-make daemon         仅编译 hamsterd
#   mingw32-make manager        仅编译 hamster_manager
#   mingw32-make test           编译并运行单元测试（JSON / 路径安全）
#   mingw32-make clean          删除编译产物
#   mingw32-make distclean      额外删除日志与测试临时目录
#   mingw32-make info           显示当前工具链与依赖探测结果
#
# 依赖（Windows + MinGW-w64）:
#   sqlite3 头文件与静态库需位于 <MINGW_HOME>/opt/include 与 <MINGW_HOME>/opt/lib
#   若自动探测失败，任选其一：
#     mingw32-make MINGW_HOME=C:/path/to/mingw64
#     在 Makefile.local 中写 MINGW_HOME := C:/path/to/mingw64   （该文件已被 .gitignore 忽略）
#
# Linux:
#   make OS=linux        （需要 libsqlite3-dev；inotify 监控已实现）

# ============================================================================
# 平台判定
# ============================================================================
ifeq ($(OS),Windows_NT)
  WIN      := 1
else
  WIN      :=
endif

# 注意：make 内建了 CC=cc，用 ?= 无法覆盖，因此这里直接赋值；
# 需要换编译器时用命令行覆盖：mingw32-make CC=clang
CC       := gcc
RM       ?= rm -f
MKDIR    ?= mkdir -p

ifeq ($(WIN),1)
  EXT        := .exe
  PLAT_LIBS  := -lws2_32
  LDFLAGS_EXTRA := -static
  CFLAGS_EXTRA  :=
else
  EXT        :=
  PLAT_LIBS  := -pthread
  LDFLAGS_EXTRA :=
  CFLAGS_EXTRA  := -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
endif

# ============================================================================
# 依赖路径探测（sqlite3）
# ============================================================================
-include Makefile.local

ifeq ($(WIN),1)
  # 未显式指定时，从 CC 的实际位置反推 MinGW 根目录
  ifeq ($(MINGW_HOME),)
    MINGW_HOME := $(patsubst %/bin/gcc.exe,%,$(patsubst %/bin/gcc,%,$(shell which $(CC) 2>/dev/null)))
  endif
  # 再退回到常见安装路径
  ifeq ($(MINGW_HOME),)
    MINGW_HOME := $(firstword $(wildcard C:/tools/msys64/mingw64 C:/msys64/mingw64 C:/mingw64 $(LOCALAPPDATA)/Programs/mingw64))
  endif
  SQLITE_INC    := $(if $(MINGW_HOME),-I$(MINGW_HOME)/opt/include)
  SQLITE_LIBDIR := $(if $(MINGW_HOME),-L$(MINGW_HOME)/opt/lib)
endif

# ============================================================================
# 目录与源文件
# ============================================================================
D_DIR  := Hamsterd
M_DIR  := Hamster Manager
# make 会把依赖里的空格当分隔符（"Hamster Manager/x.c" 被拆成两个依赖），
# 因此依赖列表必须用转义空格；recipe 里则保持普通写法并用引号包住路径。
M_DIR_ESC := Hamster\ Manager
T_DIR  := tests
B_DIR  := build

DAEMON_BIN := $(D_DIR)/hamsterd$(EXT)
MANAGER_BIN:= $(M_DIR)/hamster_manager$(EXT)
MANAGER_STAMP := $(B_DIR)/.manager.stamp

DAEMON_SRC := $(D_DIR)/hamsterd.c $(D_DIR)/hd_util.c $(D_DIR)/hd_db.c $(D_DIR)/hd_net.c $(D_DIR)/hd_crypto.c $(D_DIR)/hd_aead.c $(D_DIR)/hd_sec.c $(D_DIR)/hd_disc.c $(D_DIR)/jsonx.c $(D_DIR)/xxhash.c
DAEMON_HDR := $(D_DIR)/hd_util.h  $(D_DIR)/hd_db.h  $(D_DIR)/hd_net.h  $(D_DIR)/hd_crypto.h $(D_DIR)/hd_aead.h $(D_DIR)/hd_sec.h $(D_DIR)/hd_disc.h $(D_DIR)/jsonx.h  $(D_DIR)/xxhash.h
MANAGER_SRC:= $(M_DIR_ESC)/hamster_manager.c $(D_DIR)/jsonx.c
MANAGER_HDR:= $(D_DIR)/jsonx.h $(D_DIR)/hd_sec.h

# ============================================================================
# 编译标志
# ============================================================================
CFLAGS   ?= -O2 -Wall -Wextra -Wshadow -Wformat=2 -Wno-format-nonliteral -Wno-unused-parameter -std=c11
CFLAGS   += $(CFLAGS_EXTRA)
INC      := $(SQLITE_INC)
LIB      := $(SQLITE_LIBDIR)

# ============================================================================
# 目标
# ============================================================================
.PHONY: all daemon manager test test-unit test-crypto test-disc test-aead test-sec clean distclean info check-deps

all: check-deps daemon manager

daemon: $(DAEMON_BIN)

manager: $(MANAGER_STAMP)

$(DAEMON_BIN): $(DAEMON_SRC) $(DAEMON_HDR)
	$(CC) $(CFLAGS) $(INC) -o "$@" $(DAEMON_SRC) $(LIB) -lsqlite3 $(PLAT_LIBS) $(LDFLAGS_EXTRA)

# 用 build/ 下的时间戳文件承载"依赖"，绕开目标路径里的空格
# §8 传输加密后，代理也要链接 hd_sec（派生/记录层）；Windows 上随机数用 bcrypt
MANAGER_CRYPTO := $(D_DIR)/hd_sec.c $(D_DIR)/hd_aead.c $(D_DIR)/hd_crypto.c
ifeq ($(WIN),1)
  MANAGER_EXTRA_LIBS := -lbcrypt
else
  MANAGER_EXTRA_LIBS :=
endif

$(MANAGER_STAMP): $(MANAGER_SRC) $(MANAGER_HDR) $(MANAGER_CRYPTO)
	@$(MKDIR) "$(B_DIR)"
	$(CC) $(CFLAGS) -I$(D_DIR) -o "$(MANAGER_BIN)" "$(M_DIR)/hamster_manager.c" $(D_DIR)/jsonx.c $(MANAGER_CRYPTO) $(PLAT_LIBS) $(MANAGER_EXTRA_LIBS) $(LDFLAGS_EXTRA)
	@touch "$@"

# 依赖可用性检查
# 说明：recipe 里只放 ASCII。make 会把 recipe 按 ANSI 代码页交给 shell，
# 混入中文会让引号配对随机错乱（本机上表现为 "unexpected EOF"），
# 因此中文提示一律用 make 自己的 $(info)/$(warning)，不经过 shell。
SQLITE_PROBE := $(shell printf '\#include <sqlite3.h>\n' | $(CC) $(INC) -E -x c - >/dev/null 2>&1 && echo OK)

ifeq ($(SQLITE_PROBE),OK)
  $(info [deps] sqlite3 OK  INC=$(INC)  LIB=$(LIB))
else
  $(warning [deps] 未能确认 sqlite3 可用（编译若报 sqlite3.h 缺失，请用 MINGW_HOME=... 指定 MinGW 根目录）)
endif

check-deps:
	@echo "[deps] CC=$(CC) EXT=$(EXT) MINGW_HOME=$(MINGW_HOME)"

# 单元测试：JSON 解析/转义、路径规范化与白名单判定
# （只依赖 jsonx + hd_util + xxhash，不需要 sqlite，便于在被裁剪的环境里跑）
test: test-unit test-crypto test-disc test-aead test-sec test-log

test-disc:
	@$(MKDIR) "$(B_DIR)"
	$(CC) $(CFLAGS) -I$(D_DIR) -o "$(B_DIR)/test_disc$(EXT)" $(T_DIR)/test_disc.c $(D_DIR)/hd_disc.c $(D_DIR)/hd_crypto.c $(D_DIR)/hd_util.c $(D_DIR)/jsonx.c $(D_DIR)/xxhash.c $(PLAT_LIBS) $(LDFLAGS_EXTRA)
	@$(B_DIR)/test_disc$(EXT)

test-crypto:
	@$(MKDIR) "$(B_DIR)"
	$(CC) $(CFLAGS) -o "$(B_DIR)/test_crypto$(EXT)" $(T_DIR)/test_crypto.c $(D_DIR)/hd_crypto.c $(PLAT_LIBS)
	@$(B_DIR)/test_crypto$(EXT)

test-aead:
	@$(MKDIR) "$(B_DIR)"
	$(CC) $(CFLAGS) -I$(D_DIR) -o "$(B_DIR)/test_aead$(EXT)" $(T_DIR)/test_aead.c $(D_DIR)/hd_aead.c $(D_DIR)/hd_crypto.c $(PLAT_LIBS)
	@$(B_DIR)/test_aead$(EXT)

test-sec:
	@$(MKDIR) "$(B_DIR)"
	$(CC) $(CFLAGS) -I$(D_DIR) -o "$(B_DIR)/test_sec$(EXT)" $(T_DIR)/test_sec.c $(D_DIR)/hd_sec.c $(D_DIR)/hd_aead.c $(D_DIR)/hd_crypto.c $(PLAT_LIBS)
	@$(B_DIR)/test_sec$(EXT)

test-log:
	@$(MKDIR) "$(B_DIR)"
	$(CC) $(CFLAGS) -I$(D_DIR) -o "$(B_DIR)/test_log$(EXT)" $(T_DIR)/test_log.c $(D_DIR)/hd_util.c $(D_DIR)/jsonx.c $(D_DIR)/xxhash.c $(PLAT_LIBS) $(LDFLAGS_EXTRA)
	@$(B_DIR)/test_log$(EXT)

test-unit:
	@$(MKDIR) "$(B_DIR)"
	$(CC) $(CFLAGS) -o "$(B_DIR)/test_jsonx$(EXT)" $(T_DIR)/test_jsonx.c $(D_DIR)/jsonx.c $(D_DIR)/hd_util.c $(D_DIR)/xxhash.c $(PLAT_LIBS) $(LDFLAGS_EXTRA)
	@$(B_DIR)/test_jsonx$(EXT)

clean:
	-$(RM) "$(DAEMON_BIN)" "$(MANAGER_BIN)"
	-$(RM) "$(D_DIR)"/*.o "$(M_DIR)"/*.o
	-$(RM) -r "$(B_DIR)"

distclean: clean
	-$(RM) "$(D_DIR)"/*.log "$(D_DIR)"/*.db "$(D_DIR)"/*.db-wal "$(D_DIR)"/*.db-shm
	-$(RM) -r "$(D_DIR)/logs"
	-$(RM) -r "$(T_DIR)/tmp"

info:
	@echo "CC:          $(CC)"
	@echo "OS:          $(if $(OS),$(OS),linux)"
	@echo "CFLAGS:      $(CFLAGS)"
	@echo "MINGW_HOME:  $(MINGW_HOME)"
	@echo "SQLITE_INC:  $(INC)"
	@echo "SQLITE_LIB:  $(LIB)"
	@echo "daemon 产物: $(DAEMON_BIN)"
	@echo "manager 产物:$(MANAGER_BIN)"
