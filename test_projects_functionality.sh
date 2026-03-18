#!/bin/bash

# 项目功能测试脚本 - 验证8个C/C++项目的实际运行情况
# 日期: 2026年3月13日

CODE_DIR="/home/op/CKGFuzzer/code"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "========================================="
echo "测试8个项目的运行功能"
echo "========================================="
echo ""

# 1. zlib - 测试压缩功能
echo -e "${YELLOW}[1/8] 测试 zlib...${NC}"
cd "$CODE_DIR/zlib" || exit 1
if [ -f "libz.a" ]; then
    # 创建测试文件
    echo "Hello, zlib test!" > test_input.txt
    # 使用example程序测试（如果存在）
    if [ -f "example" ]; then
        ./example && echo -e "${GREEN}✓ zlib 运行正常${NC}" || echo -e "${RED}✗ zlib 测试失败${NC}"
    else
        echo -e "${YELLOW}⚠ zlib 库文件存在，但无测试程序${NC}"
    fi
else
    echo -e "${RED}✗ zlib 库文件不存在${NC}"
fi
echo ""

# 2. cJSON - 测试JSON解析
echo -e "${YELLOW}[2/8] 测试 cJSON...${NC}"
cd "$CODE_DIR/cJSON/build" || exit 1
if [ -f "libcjson.a" ]; then
    # 创建简单的测试程序
    cat > /tmp/test_cjson.c << 'EOF'
#include "../cJSON.h"
#include <stdio.h>
int main() {
    cJSON *json = cJSON_Parse("{\"name\":\"test\",\"value\":123}");
    if (json) {
        char *str = cJSON_Print(json);
        printf("Parsed: %s\n", str);
        cJSON_Delete(json);
        free(str);
        return 0;
    }
    return 1;
}
EOF
    gcc /tmp/test_cjson.c -I.. -L. -lcjson -lm -o /tmp/test_cjson 2>/dev/null
    if [ -f /tmp/test_cjson ] && /tmp/test_cjson; then
        echo -e "${GREEN}✓ cJSON 运行正常${NC}"
    else
        echo -e "${RED}✗ cJSON 测试失败${NC}"
    fi
else
    echo -e "${RED}✗ cJSON 库文件不存在${NC}"
fi
echo ""

# 3. c-ares - 测试DNS解析工具
echo -e "${YELLOW}[3/8] 测试 c-ares...${NC}"
cd "$CODE_DIR/c-ares/build/bin" || exit 1
if [ -f "adig" ]; then
    # 测试DNS查询
    if ./adig google.com | grep -q "google.com"; then
        echo -e "${GREEN}✓ c-ares DNS解析正常${NC}"
    else
        echo -e "${RED}✗ c-ares DNS解析失败${NC}"
    fi
else
    echo -e "${RED}✗ c-ares 工具不存在${NC}"
fi
echo ""

# 4. libpcap - 检查库文件
echo -e "${YELLOW}[4/8] 测试 libpcap...${NC}"
cd "$CODE_DIR/libpcap" || exit 1
if [ -f "libpcap.a" ]; then
    # libpcap需要权限才能抓包，只检查库是否正确链接
    echo -e "${YELLOW}⚠ libpcap 库存在（需要root权限才能测试抓包功能）${NC}"
else
    echo -e "${RED}✗ libpcap 库文件不存在${NC}"
fi
echo ""

# 5. libtiff - 测试TIFF工具
echo -e "${YELLOW}[5/8] 测试 libtiff...${NC}"
cd "$CODE_DIR/libtiff/mybuild/tools" || exit 1
if [ -f "tiffinfo" ]; then
    # tiffinfo显示版本信息
    if ./tiffinfo -h 2>&1 | grep -i "tiff"; then
        echo -e "${GREEN}✓ libtiff 工具运行正常${NC}"
    else
        echo -e "${RED}✗ libtiff 工具测试失败${NC}"
    fi
else
    echo -e "${RED}✗ libtiff 工具不存在${NC}"
fi
echo ""

# 6. libvpx - 测试编解码工具
echo -e "${YELLOW}[6/8] 测试 libvpx...${NC}"
cd "$CODE_DIR/libvpx" || exit 1
if [ -f "libvpx.a" ]; then
    echo -e "${YELLOW}⚠ libvpx 库存在（需要视频文件才能完整测试编解码）${NC}"
else
    echo -e "${RED}✗ libvpx 库文件不存在${NC}"
fi
echo ""

# 7. Little-CMS - 测试颜色管理工具
echo -e "${YELLOW}[7/8] 测试 Little-CMS...${NC}"
cd "$CODE_DIR/Little-CMS" || exit 1
if [ -f "src/.libs/liblcms2.a" ]; then
    if [ -f "utils/tificc/tificc" ]; then
        ./utils/tificc/tificc 2>&1 | grep -i "usage" && \
        echo -e "${GREEN}✓ Little-CMS 工具运行正常${NC}" || \
        echo -e "${YELLOW}⚠ Little-CMS 库存在${NC}"
    else
        echo -e "${YELLOW}⚠ Little-CMS 库存在${NC}"
    fi
else
    echo -e "${RED}✗ Little-CMS 库文件不存在${NC}"
fi
echo ""

# 8. curl - 测试HTTP请求
echo -e "${YELLOW}[8/8] 测试 curl...${NC}"
cd "$CODE_DIR/curl/build/src" || exit 1
if [ -f "curl" ]; then
    # 测试curl版本和简单请求
    if ./curl --version | grep -q "curl"; then
        echo -e "${GREEN}✓ curl 工具运行正常${NC}"
        # 测试实际HTTP请求（可选）
        # ./curl -I https://www.google.com 2>/dev/null && echo "  HTTP请求测试通过"
    else
        echo -e "${RED}✗ curl 工具测试失败${NC}"
    fi
else
    echo -e "${RED}✗ curl 工具不存在${NC}"
fi
echo ""

echo "========================================="
echo "功能测试完成"
echo "========================================="
