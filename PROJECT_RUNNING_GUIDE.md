# 8个C/C++项目运行指南

## 📊 验证结果总结

### ✅ 可直接运行的项目（5个）
1. **zlib** - 压缩库，有测试程序
2. **c-ares** - DNS解析库，有命令行工具
3. **libtiff** - TIFF图像库，有图像处理工具
4. **curl** - HTTP客户端工具
5. **cJSON** - JSON解析库（需要编写代码调用）

### ⚠️ 需要特定条件的项目（3个）
6. **libpcap** - 网络抓包库（需要root权限）
7. **libvpx** - VP8/VP9编解码库（需要视频文件）
8. **Little-CMS** - 颜色管理库（需要ICC配置文件）

---

## 🚀 运行示例

### 1. c-ares (DNS解析工具)

```bash
# 查询域名的A记录
/home/op/CKGFuzzer/code/c-ares/build/bin/adig google.com

# 查询MX记录
/home/op/CKGFuzzer/code/c-ares/build/bin/adig -t MX gmail.com

# 主机名解析
/home/op/CKGFuzzer/code/c-ares/build/bin/ahost baidu.com

# 反向DNS查询
/home/op/CKGFuzzer/code/c-ares/build/bin/adig -x 8.8.8.8
```

**输出示例：**
```
id: 31936
flags: qr rd ra
opcode: QUERY
rcode: NOERROR
Questions:
        google.com     .                A
Answers:
        google.com     .        176     A       142.250.73.142
```

---

### 2. zlib (压缩/解压缩)

```bash
cd /home/op/CKGFuzzer/code/zlib

# 测试压缩功能
./example

# 使用库编写测试程序
cat > test_zlib.c << 'EOF'
#include <stdio.h>
#include <string.h>
#include "zlib.h"

int main() {
    const char *data = "Hello, zlib compression!";
    unsigned char compressed[100];
    unsigned char decompressed[100];
    
    uLongf comp_len = sizeof(compressed);
    uLongf decomp_len = sizeof(decompressed);
    
    // 压缩
    compress(compressed, &comp_len, (unsigned char*)data, strlen(data));
    printf("Original: %ld bytes, Compressed: %ld bytes\n", 
           strlen(data), comp_len);
    
    // 解压
    uncompress(decompressed, &decomp_len, compressed, comp_len);
    printf("Decompressed: %s\n", decompressed);
    return 0;
}
EOF

gcc test_zlib.c -L. -lz -o test_zlib
./test_zlib
```

---

### 3. libtiff (TIFF图像处理)

```bash
cd /home/op/CKGFuzzer/code/libtiff/mybuild/tools

# 查看TIFF文件信息
./tiffinfo -h  # 查看帮助

# 如果有TIFF文件
# ./tiffinfo image.tiff
# ./tiffcp input.tiff output.tiff
# ./tiff2pdf input.tiff -o output.pdf
```

**可用工具：**
- `tiffinfo` - 显示TIFF文件信息
- `tiffcp` - 复制/转换TIFF文件
- `tiff2pdf` - TIFF转PDF
- `tiffcrop` - 裁剪TIFF图像
- `tiffset` - 设置TIFF标签

---

### 4. curl (HTTP客户端)

```bash
cd /home/op/CKGFuzzer/code/curl/build/src

# 查看版本
./curl --version

# 获取网页
./curl https://www.google.com

# 查看HTTP头
./curl -I https://www.baidu.com

# 下载文件
./curl -O https://example.com/file.txt

# POST请求
./curl -X POST -d "key=value" https://httpbin.org/post
```

---

### 5. cJSON (JSON解析库)

需要编写C程序调用：

```bash
cd /home/op/CKGFuzzer/code/cJSON

# 创建测试程序
cat > test_cjson.c << 'EOF'
#include "cJSON.h"
#include <stdio.h>

int main() {
    // 创建JSON对象
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "name", "c-ares");
    cJSON_AddNumberToObject(root, "version", 1.0);
    
    // 转换为字符串
    char *json_str = cJSON_Print(root);
    printf("JSON: %s\n", json_str);
    
    // 清理
    free(json_str);
    cJSON_Delete(root);
    return 0;
}
EOF

gcc test_cjson.c build/libcjson.a -I. -lm -o test_cjson
./test_cjson
```

---

### 6. libpcap (网络抓包)

```bash
cd /home/op/CKGFuzzer/code/libpcap

# 需要root权限
# sudo ./tcpdump -i eth0 -c 10

# 编写简单的抓包程序
cat > test_pcap.c << 'EOF'
#include <pcap.h>
#include <stdio.h>

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    
    // 获取网络设备列表
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error: %s\n", errbuf);
        return 1;
    }
    
    printf("Network interfaces:\n");
    for(pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        printf("  %s", d->name);
        if (d->description)
            printf(" (%s)", d->description);
        printf("\n");
    }
    
    pcap_freealldevs(alldevs);
    return 0;
}
EOF

gcc test_pcap.c -L. -lpcap -o test_pcap
./test_pcap
```

---

### 7. libvpx (VP8/VP9编解码)

```bash
cd /home/op/CKGFuzzer/code/libvpx

# 需要视频文件
# ./vpxenc --codec=vp9 input.yuv -o output.webm
# ./vpxdec output.webm -o decoded.yuv
```

---

### 8. Little-CMS (颜色管理)

```bash
cd /home/op/CKGFuzzer/code/Little-CMS

# 需要ICC配置文件
# ./utils/tificc/tificc input.tif output.tif profile.icc
```

---

## 📝 编译状态vs运行状态

| 项目 | 编译状态 | 运行状态 | 说明 |
|------|---------|---------|------|
| zlib | ✅ | ✅ | 有example测试程序，可直接运行 |
| cJSON | ✅ | ✅ | 库可用，需编写代码测试 |
| c-ares | ✅ | ✅ | 提供3个命令行工具，完全可用 |
| libpcap | ✅ | ⚠️ | 需要root权限抓包 |
| libtiff | ✅ | ✅ | 提供多个图像处理工具 |
| libvpx | ✅ | ⚠️ | 需要视频文件测试 |
| Little-CMS | ✅ | ⚠️ | 需要ICC配置文件 |
| curl | ✅ | ✅ | HTTP客户端完全可用 |

---

## 🔍 验证脚本

```bash
# 编译验证
/home/op/CKGFuzzer/verify_projects.sh

# 功能测试
/home/op/CKGFuzzer/test_projects_functionality.sh

# 项目结构检查
/home/op/CKGFuzzer/check_projects_structure.sh
```

---

## 💡 总结

**编译成功** ≠ **可以运行**

- ✅ **编译成功**：代码无语法错误，依赖正确
- ✅ **功能正常**：需要运行测试用例或实际使用验证
- ⚠️ **部分项目**：需要特定输入（文件、权限、网络等）

对于fuzzing测试，建议重点关注：
1. **c-ares** - DNS解析，有明确的输入输出
2. **cJSON** - JSON解析，输入格式明确
3. **libtiff** - 图像文件解析
4. **curl** - HTTP协议处理

这些项目都有清晰的API和输入格式，适合进行模糊测试。
