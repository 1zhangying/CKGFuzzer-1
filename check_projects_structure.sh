#!/bin/bash

# 快速检查8个项目的构建系统类型
CODE_DIR="/home/op/CKGFuzzer/code"

echo "========================================="
echo "检查8个项目的构建系统"
echo "========================================="
echo ""

for project in zlib cJSON c-ares libpcap libtiff libvpx Little-CMS curl; do
    echo "[$project]"
    cd "$CODE_DIR/$project" 2>/dev/null || { echo "  ✗ 项目目录不存在"; echo ""; continue; }
    
    if [ -f "CMakeLists.txt" ]; then
        echo "  构建系统: CMake"
    elif [ -f "configure.ac" ] || [ -f "configure.in" ]; then
        echo "  构建系统: Autotools (需要 autogen/buildconf)"
        [ -f "configure" ] && echo "  configure: ✓ 已生成" || echo "  configure: ✗ 需要生成"
    elif [ -f "configure" ]; then
        echo "  构建系统: Configure"
    elif [ -f "Makefile" ]; then
        echo "  构建系统: Makefile"
    else
        echo "  构建系统: 未知"
    fi
    
    # 检查依赖
    if [ -f "README.md" ]; then
        echo "  文档: ✓"
    fi
    
    echo ""
done
