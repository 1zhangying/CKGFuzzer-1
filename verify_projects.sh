#!/bin/bash

# 项目验证脚本 - 验证8个C/C++项目是否能够正常编译
# 日期: 2026年3月13日

CODE_DIR="/home/op/CKGFuzzer/code"
LOG_DIR="/home/op/CKGFuzzer/verification_logs"
mkdir -p "$LOG_DIR"

# 颜色输出
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================="
echo "开始验证8个项目的编译情况"
echo "========================================="
echo ""

# 汇总结果
declare -A RESULTS

# 1. zlib - 使用 configure && make
echo -e "${YELLOW}[1/8] 验证 zlib...${NC}"
cd "$CODE_DIR/zlib" || exit 1
make clean > /dev/null 2>&1
./configure --prefix="$PWD/install" > "$LOG_DIR/zlib_configure.log" 2>&1
if make -j$(nproc) > "$LOG_DIR/zlib_build.log" 2>&1; then
    echo -e "${GREEN}✓ zlib 编译成功${NC}"
    RESULTS[zlib]="成功"
else
    echo -e "${RED}✗ zlib 编译失败，查看日志: $LOG_DIR/zlib_build.log${NC}"
    RESULTS[zlib]="失败"
fi
echo ""

# 2. cJSON - 使用 CMake
echo -e "${YELLOW}[2/8] 验证 cJSON...${NC}"
cd "$CODE_DIR/cJSON" || exit 1
rm -rf build && mkdir -p build && cd build
if cmake .. -DENABLE_CJSON_TEST=Off -DBUILD_SHARED_LIBS=Off > "$LOG_DIR/cjson_cmake.log" 2>&1 && \
   make -j$(nproc) > "$LOG_DIR/cjson_build.log" 2>&1; then
    echo -e "${GREEN}✓ cJSON 编译成功${NC}"
    RESULTS[cJSON]="成功"
else
    echo -e "${RED}✗ cJSON 编译失败，查看日志: $LOG_DIR/cjson_build.log${NC}"
    RESULTS[cJSON]="失败"
fi
echo ""

# 3. c-ares - 使用 CMake
echo -e "${YELLOW}[3/8] 验证 c-ares...${NC}"
cd "$CODE_DIR/c-ares" || exit 1
rm -rf build && mkdir -p build && cd build
if cmake .. -DCARES_STATIC=ON -DCARES_BUILD_TESTS=OFF > "$LOG_DIR/c-ares_cmake.log" 2>&1 && \
   make -j$(nproc) > "$LOG_DIR/c-ares_build.log" 2>&1; then
    echo -e "${GREEN}✓ c-ares 编译成功${NC}"
    RESULTS[c-ares]="成功"
else
    echo -e "${RED}✗ c-ares 编译失败，查看日志: $LOG_DIR/c-ares_build.log${NC}"
    RESULTS[c-ares]="失败"
fi
echo ""

# 4. libpcap - 使用 configure && make
echo -e "${YELLOW}[4/8] 验证 libpcap...${NC}"
cd "$CODE_DIR/libpcap" || exit 1
make clean > /dev/null 2>&1
if [ ! -f configure ]; then
    ./autogen.sh > "$LOG_DIR/libpcap_autogen.log" 2>&1
fi
./configure --prefix="$PWD/install" > "$LOG_DIR/libpcap_configure.log" 2>&1
if make -j$(nproc) > "$LOG_DIR/libpcap_build.log" 2>&1; then
    echo -e "${GREEN}✓ libpcap 编译成功${NC}"
    RESULTS[libpcap]="成功"
else
    echo -e "${RED}✗ libpcap 编译失败，查看日志: $LOG_DIR/libpcap_build.log${NC}"
    RESULTS[libpcap]="失败"
fi
echo ""

# 5. libtiff - 使用 CMake (注意：源码中有build目录，需要使用其他名称)
echo -e "${YELLOW}[5/8] 验证 libtiff...${NC}"
cd "$CODE_DIR/libtiff" || exit 1
rm -rf mybuild && mkdir -p mybuild && cd mybuild
if cmake .. -DBUILD_SHARED_LIBS=OFF -Dtiff-tests=OFF > "$LOG_DIR/libtiff_cmake.log" 2>&1 && \
   make -j$(nproc) > "$LOG_DIR/libtiff_build.log" 2>&1; then
    echo -e "${GREEN}✓ libtiff 编译成功${NC}"
    RESULTS[libtiff]="成功"
else
    echo -e "${RED}✗ libtiff 编译失败，查看日志: $LOG_DIR/libtiff_build.log${NC}"
    RESULTS[libtiff]="失败"
fi
echo ""

# 6. libvpx - 使用 configure && make
echo -e "${YELLOW}[6/8] 验证 libvpx...${NC}"
cd "$CODE_DIR/libvpx" || exit 1
make clean > /dev/null 2>&1
if [ ! -f configure ]; then
    echo -e "${RED}✗ libvpx 缺少 configure 脚本${NC}"
    RESULTS[libvpx]="失败(无configure)"
else
    ./configure --disable-examples --disable-unit-tests --prefix="$PWD/install" > "$LOG_DIR/libvpx_configure.log" 2>&1
    if make -j$(nproc) > "$LOG_DIR/libvpx_build.log" 2>&1; then
        echo -e "${GREEN}✓ libvpx 编译成功${NC}"
        RESULTS[libvpx]="成功"
    else
        echo -e "${RED}✗ libvpx 编译失败，查看日志: $LOG_DIR/libvpx_build.log${NC}"
        RESULTS[libvpx]="失败"
    fi
fi
echo ""

# 7. Little-CMS - 使用 configure && make
echo -e "${YELLOW}[7/8] 验证 Little-CMS...${NC}"
cd "$CODE_DIR/Little-CMS" || exit 1
make clean > /dev/null 2>&1
if [ ! -f configure ]; then
    ./autogen.sh > "$LOG_DIR/lcms_autogen.log" 2>&1
fi
if [ -f configure ]; then
    ./configure --prefix="$PWD/install" > "$LOG_DIR/lcms_configure.log" 2>&1
    if make -j$(nproc) > "$LOG_DIR/lcms_build.log" 2>&1; then
        echo -e "${GREEN}✓ Little-CMS 编译成功${NC}"
        RESULTS[Little-CMS]="成功"
    else
        echo -e "${RED}✗ Little-CMS 编译失败，查看日志: $LOG_DIR/lcms_build.log${NC}"
        RESULTS[Little-CMS]="失败"
    fi
else
    echo -e "${RED}✗ Little-CMS 无法生成 configure${NC}"
    RESULTS[Little-CMS]="失败(无configure)"
fi
echo ""

# 8. curl - 使用 CMake 或 configure
echo -e "${YELLOW}[8/8] 验证 curl...${NC}"
cd "$CODE_DIR/curl" || exit 1
rm -rf build && mkdir -p build && cd build
if cmake .. -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF -DCURL_DISABLE_TESTS=ON > "$LOG_DIR/curl_cmake.log" 2>&1 && \
   make -j$(nproc) > "$LOG_DIR/curl_build.log" 2>&1; then
    echo -e "${GREEN}✓ curl 编译成功${NC}"
    RESULTS[curl]="成功"
else
    echo -e "${RED}✗ curl 编译失败，查看日志: $LOG_DIR/curl_build.log${NC}"
    RESULTS[curl]="失败"
fi
echo ""

# 输出汇总结果
echo "========================================="
echo "验证结果汇总"
echo "========================================="
SUCCESS_COUNT=0
for project in zlib cJSON c-ares libpcap libtiff libvpx Little-CMS curl; do
    result="${RESULTS[$project]}"
    if [[ "$result" == "成功" ]]; then
        echo -e "$project: ${GREEN}$result${NC}"
        ((SUCCESS_COUNT++))
    else
        echo -e "$project: ${RED}$result${NC}"
    fi
done
echo ""
echo "成功: $SUCCESS_COUNT/8"
echo "日志目录: $LOG_DIR"
echo "========================================="
