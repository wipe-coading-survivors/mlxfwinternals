ifeq ($(shell test -f /run/.containerenv && echo y),y)
CRE ?= podman-remote
HOSTCURDIR := $(patsubst /run/host/%,%,$(CURDIR))
else
CRE ?= podman
HOSTCURDIR := $(CURDIR)
endif

GHIDRA_IMAGE ?= mlxini-ghidra-irisc
GHIDRA_CONTAINER_DIR ?= ../ghidra-container

CH341_IMAGE ?= mlxini-ch341i2c

-include local.mk

GHIDRA_CONTAINER_HOSTDIR := $(patsubst /run/host/%,%,$(abspath $(GHIDRA_CONTAINER_DIR)))

.PHONY: slaspec-gen ghidra-scripts-guard ghidra-decode ghidra-decode-dev ghidra-re ghidra-re-script ghidra-import-file irisc-crosscheck ch341i2c-run ch341i2c-script test test-fast test-parallel test-no-sensitive public corpus corpus-check

# Канон slaspec — патч scripts/irisc/iRISC.slaspec.patch (tracked); полные
# файлы — untracked-генерация из патча (upstream: пин-sha256-гейт, source —
# env SLASPEC_UPSTREAM / --upstream, default raw.githubusercontent; кэш
# build/slaspec-cache). Пререквизит тест-целей: офлайн без кэша — warn
# (slaspec-зависимые тесты skip), integrity-отказ (sha-мисматч / patch-отказ)
# — fail.
slaspec-gen:
	@rc=0; python3 scripts/irisc/slaspec_patch.py gen || rc=$$?; \
	case $$rc in \
		0) ;; \
		2) echo "slaspec-gen: WARNING: upstream source unavailable (offline, no cache in build/slaspec-cache) - slaspec-dependent tests will skip";; \
		*) exit $$rc;; \
	esac

# USB-программатор (PACBTECH SFP Programmer, CH341 1a86:5512) должен быть
# воткнут в хост. --privileged вместо --device: rootless-podman не пускает
# usbfs-ноды (major 189) через device-cgroup даже с MODE=0666; на хосте
# желателен udev-rule 99-ch341-sfp.rules (MODE=0666) и отцеплённый spi-ch341.
# Примеры:
#   make ch341i2c-run ARGS="--addr 0x50 probe"
#   make ch341i2c-run ARGS="--addr 0x50 read 256 --decode-a0"
#   make ch341i2c-run ARGS="--addr 0x51 read 256"
#   make ch341i2c-run ARGS="--addr 0x50 write image.bin"
ch341i2c-run:
	@test -n "$(ARGS)" || { echo "usage: make ch341i2c-run ARGS=\"--addr 0x50 read 256\""; exit 2; }
	@$(CRE) image exists $(CH341_IMAGE) >/dev/null 2>&1 || { echo "image '$(CH341_IMAGE)' missing: build it in ~/git/IMPLEMENTATION/ch341i2c-container (make image)"; exit 1; }
	$(CRE) run --rm --privileged -v $(HOSTCURDIR):/work:z $(CH341_IMAGE) $(ARGS)

# Диагностические python-скрипты поверх ch341i2c-образа (entrypoint
# переопределён на python3). Пример:
#   make ch341i2c-script SCRIPT="diag_wr_ack.py --addr 0x51 --offset 222 --data 6400"
ch341i2c-script:
	@test -n "$(SCRIPT)" || { echo "usage: make ch341i2c-script SCRIPT=\"<script.py args>\""; exit 2; }
	@$(CRE) image exists $(CH341_IMAGE) >/dev/null 2>&1 || { echo "image '$(CH341_IMAGE)' missing: build it in ~/git/IMPLEMENTATION/ch341i2c-container (make image)"; exit 1; }
	$(CRE) run --rm --privileged -v $(HOSTCURDIR):/work:z --entrypoint python3 $(CH341_IMAGE) /work/scripts/$(SCRIPT)

GHIDRA_SCRIPTS_MOUNT ?=
GHIDRA_SCRIPTS_MOUNT_DEV = -v $(GHIDRA_CONTAINER_HOSTDIR)/scripts/ghidra:/opt/ghidra/Ghidra/Features/Base/ghidra_scripts:z

IRISC_CROSSCHECK_SLASPEC ?= both

test-no-sensitive:
	sh scripts/test-no-sensitive.sh

# Publication pipeline (spec §3, publication-branch-design): orphan snapshot
# of the filtered+obfuscated tree → push-цель PUBLIC_REMOTE (local.mk) или
# per-run override `make public REMOTE=<url>`; DRY=1 — всё до push, push
# печатается, не исполняется. BRANCH=public (default, без force) или
# BRANCH=public-next (автоматизация: force-with-lease из свежего ls-remote,
# parent неизменно от public, zero-diff skip); без общей истории с master
# (pre-push hook ограничивает).
BRANCH ?= public
public:
	@test -n "$(PUBLIC_REMOTE)$(REMOTE)" || { echo "public: PUBLIC_REMOTE is not set - set it in local.mk or pass REMOTE=<url>"; exit 2; }
	python3 -m scripts.publish.publish --remote '$(if $(REMOTE),$(REMOTE),$(PUBLIC_REMOTE))'$(if $(DRY), --dry) --branch '$(BRANCH)'

test: slaspec-gen test-no-sensitive
	python3 -m pytest tests/

# SerDes corpus (roadmap 190, arc A: spec 2026-11-11-serdes-corpus-a):
# one-command reproducible decompilation corpus over the pinned image
# manifest (scripts/corpus/manifest.py). Output: build/corpus/ (git-ignored);
# summary manifest scripts/corpus/corpus_manifest.json (committed).
# Очистка перед пересборкой — только через scripts/safe-rm (rm-rf-guard).
corpus:
	@mkdir -p $(CURDIR)/build/corpus
	scripts/safe-rm --under $(CURDIR)/build/corpus $(CURDIR)/build/corpus
	python3 -m scripts.corpus.build_corpus

corpus-check:
	python3 -m scripts.corpus.build_corpus --check

test-fast: slaspec-gen test-no-sensitive
	python3 -m pytest tests/ -m "not slow"

# test-parallel: требует python3-pytest-xdist (RPM Fedora)
test-parallel: slaspec-gen test-no-sensitive
	python3 -m pytest tests/ -n auto --dist loadscope

NAME ?= $(SECTION)
GHIDRA_SCRIPTS_MOUNT_RE = -v $(GHIDRA_CONTAINER_HOSTDIR)/scripts/ghidra:/opt/ghidra/Ghidra/Features/Base/ghidra_scripts:z

# Монтирующие цели требуют чекаут компаньона: иначе podman молча шадоит
# запечённые в образ скрипты пустым каталогом.
ghidra-scripts-guard:
	@test -d "$(GHIDRA_CONTAINER_DIR)/scripts/ghidra" || { echo "ghidra-container checkout missing: $(GHIDRA_CONTAINER_DIR)/scripts/ghidra not found (clone the ghidra-container companion or set GHIDRA_CONTAINER_DIR in local.mk)"; exit 2; }

ghidra-decode-dev: ghidra-scripts-guard
ghidra-decode-dev: GHIDRA_SCRIPTS_MOUNT=$(GHIDRA_SCRIPTS_MOUNT_DEV)

ghidra-decode ghidra-decode-dev:
	@test -n "$(IMG)" -a -n "$(SECTION)" || { echo "usage: make ghidra-decode IMG=<image> SECTION=<0xNN>  (пример: SECTION=0x03)"; exit 2; }
	@$(CRE) image exists $(GHIDRA_IMAGE) >/dev/null 2>&1 || { echo "image '$(GHIDRA_IMAGE)' missing: build it in ~/git/IMPLEMENTATION/ghidra-container (make image)"; exit 1; }
	python3 mlxfwutil.py extract -s $(SECTION) --raw -o build/ghidra-$(SECTION).bin $(IMG)
	$(CRE) run --rm -v $(HOSTCURDIR):/work:z $(GHIDRA_SCRIPTS_MOUNT) -w /work $(GHIDRA_IMAGE) /work/build/ghidra-$(SECTION).bin

ghidra-re: ghidra-scripts-guard
	@test -n "$(IMG)" -a -n "$(SECTION)" || { echo "usage: make ghidra-re IMG=<image> SECTION=<0xNN> [NAME=<label>]"; exit 2; }
	@$(CRE) image exists $(GHIDRA_IMAGE) >/dev/null 2>&1 || { echo "image '$(GHIDRA_IMAGE)' missing: build it in ~/git/IMPLEMENTATION/ghidra-container (make image)"; exit 1; }
	mkdir -p build/ghidra-proj/$(NAME)
	python3 mlxfwutil.py extract -s $(SECTION) --raw -o build/ghidra-$(NAME).bin $(IMG)
	$(CRE) run --rm --entrypoint /usr/local/bin/ghidra-re -v $(HOSTCURDIR):/work:z $(GHIDRA_SCRIPTS_MOUNT_RE) -w /work $(GHIDRA_IMAGE) import /work/build/ghidra-$(NAME).bin /work/build/ghidra-proj/$(NAME)

ghidra-import-file: ghidra-scripts-guard
	@test -n "$(FILE)" -a -n "$(NAME)" || { echo "usage: make ghidra-import-file FILE=<path> NAME=<label> [PRE=<script>]  (импорт готового файла в Ghidra-проект, iRISC)"; exit 2; }
	@$(CRE) image exists $(GHIDRA_IMAGE) >/dev/null 2>&1 || { echo "image '$(GHIDRA_IMAGE)' missing: build it in ~/git/IMPLEMENTATION/ghidra-container (make image)"; exit 1; }
	mkdir -p build/ghidra-proj/$(NAME)
	cp "$(FILE)" build/ghidra-$(NAME).bin
	$(CRE) run --rm --entrypoint /usr/local/bin/ghidra-re -v $(HOSTCURDIR):/work:z $(GHIDRA_SCRIPTS_MOUNT_RE) -w /work $(GHIDRA_IMAGE) import /work/build/ghidra-$(NAME).bin /work/build/ghidra-proj/$(NAME) iRISC:BE:32:default $(PRE)

ghidra-re-script: ghidra-scripts-guard
	@test -n "$(SECTION)" -a -n "$(SCRIPT)" || { echo "usage: make ghidra-re-script SECTION=<0xNN> SCRIPT=<X.java> [NAME=<label>] [RANGE=<lo> <hi>]"; exit 2; }
	@test -d build/ghidra-proj/$(NAME) || { echo "project missing: make ghidra-re IMG=<image> SECTION=$(SECTION) NAME=$(NAME) first"; exit 2; }
	@$(CRE) image exists $(GHIDRA_IMAGE) >/dev/null 2>&1 || { echo "image '$(GHIDRA_IMAGE)' missing: build it in ~/git/IMPLEMENTATION/ghidra-container (make image)"; exit 1; }
	@if [ -n "$(RANGE)" ]; then echo "$(RANGE)" > build/ghidra-range.txt; elif [ -n "$(CLEAR)" ]; then rm -f build/ghidra-range.txt; fi
	$(CRE) run --rm --entrypoint /usr/local/bin/ghidra-re -v $(HOSTCURDIR):/work:z $(GHIDRA_SCRIPTS_MOUNT_RE) -w /work $(GHIDRA_IMAGE) script /work/build/ghidra-proj/$(NAME) ghidra-$(NAME).bin $(SCRIPT)

irisc-crosscheck: slaspec-gen
	@test -n "$(IMG)" || { echo "usage: make irisc-crosscheck IMG=<image> [IRISC_CROSSCHECK_SLASPEC={repo,upstream,both}] [OUT=<report.json>]"; exit 2; }
	@$(CRE) image exists $(GHIDRA_IMAGE) >/dev/null 2>&1 || { echo "image '$(GHIDRA_IMAGE)' missing: build it in ~/git/IMPLEMENTATION/ghidra-container (make image)"; exit 1; }
	python3 scripts/irisc/crosscheck.py --image $(IMG) --slaspec $(IRISC_CROSSCHECK_SLASPEC) --ghidra-image $(GHIDRA_IMAGE) --out $(if $(OUT),$(OUT),build/irisc-crosscheck-$(notdir $(IMG)).json)
