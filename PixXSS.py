#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import subprocess
import os
import sys
import logging
import shutil
import tempfile
from pathlib import Path
from typing import List, Tuple, Dict, Optional

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("pixxss.log", mode="a", encoding="utf-8")
    ]
)
logger = logging.getLogger(__name__)

# 自定义HelpFormatter
class CustomHelpFormatter(argparse.RawDescriptionHelpFormatter):
    def add_usage(self, usage, actions, groups, prefix=None):
        if prefix is None:
            prefix = "用法: "
        return super().add_usage(usage, actions, groups, prefix)

# 定义支持的格式和元数据字段（已更新）
SUPPORTED_FORMATS = {
    "JPEG": {
        "EXIF": {
            "ImageDescription": "图片描述",
            "UserComment": "用户注释(支持Unicode)",
            "Artist": "作者信息",
            "Copyright": "版权信息",
            "Software": "软件信息"
        },
        "IPTC": {
            "Caption/Abstract": "标题/摘要",
            "Keywords": "关键词",
            "By-line": "作者",
            "ObjectName": "对象名称",
            "Headline": "头条标题",
            "CopyrightNotice": "版权声明"
        },
        "XMP": {
            "dc:title": "标题(Dublin Core)",
            "dc:description": "描述(Dublin Core)",
            "dc:creator": "创建者",
            "dc:subject": "主题",
            "dc:rights": "版权信息"
        }
    },
    "PNG": {
        "tEXt": {
            "Title": "标题(未压缩)",
            "Author": "作者(未压缩)",
            "Description": "描述(未压缩)",
            "Comment": "注释(未压缩)",
            "Software": "软件信息(未压缩)",
            "Creation Time": "创建时间(未压缩)"
        },
        "zTXt": {
            "Title": "标题(压缩)",
            "Author": "作者(压缩)",
            "Description": "描述(压缩)",
            "Comment": "注释(压缩)",
            "Software": "软件信息(压缩)",
            "Creation Time": "创建时间(压缩)"
        },
        "iTXt": {
            "Title": "标题(国际化)",
            "Author": "作者(国际化)",
            "Description": "描述(国际化)",
            "Comment": "注释(国际化)",
            "Software": "软件信息(国际化)",
            "Creation Time": "创建时间(国际化)"
        },
        "XMP": {
            "dc:title": "标题(Dublin Core)",
            "dc:description": "描述(Dublin Core)",
            "dc:creator": "创建者",
            "dc:subject": "主题",
            "dc:rights": "版权信息"
        }
    },
    "GIF": {
        "Comment Extension": {
            "Comment": "注释扩展块"
        },
        "XMP": {
            "dc:title": "标题(Dublin Core)",
            "dc:description": "描述(Dublin Core)",
            "dc:creator": "创建者",
            "dc:subject": "主题",
            "dc:rights": "版权信息"
        }
    },
    "WEBP": {
        "EXIF": {
            "ImageDescription": "图片描述",
            "UserComment": "用户注释",
            "Artist": "作者信息",
            "Copyright": "版权信息",
            "Software": "软件信息"
        },
        "XMP": {
            "dc:title": "标题(Dublin Core)",
            "dc:description": "描述(Dublin Core)",
            "dc:creator": "创建者",
            "dc:subject": "主题",
            "dc:rights": "版权信息"
        }
    },
    "TIFF": {
        "EXIF": {
            "ImageDescription": "图片描述",
            "UserComment": "用户注释",
            "Artist": "作者信息",
            "Copyright": "版权信息",
            "Software": "软件信息"
        },
        "IPTC": {
            "Caption/Abstract": "标题/摘要",
            "Keywords": "关键词",
            "By-line": "作者",
            "ObjectName": "对象名称",
            "Headline": "头条标题",
            "CopyrightNotice": "版权声明"
        },
        "XMP": {
            "dc:title": "标题(Dublin Core)",
            "dc:description": "描述(Dublin Core)",
            "dc:creator": "创建者",
            "dc:subject": "主题",
            "dc:rights": "版权信息"
        }
    },
    "HEIF": {
        "EXIF": {
            "ImageDescription": "图片描述",
            "UserComment": "用户注释",
            "Artist": "作者信息",
            "Copyright": "版权信息",
            "Software": "软件信息"
        },
        "XMP": {
            "dc:title": "标题(Dublin Core)",
            "dc:description": "描述(Dublin Core)",
            "dc:creator": "创建者",
            "dc:subject": "主题",
            "dc:rights": "版权信息"
        }
    },
    "AVIF": {
        "EXIF": {
            "ImageDescription": "图片描述",
            "UserComment": "用户注释",
            "Artist": "作者信息",
            "Copyright": "版权信息",
            "Software": "软件信息"
        },
        "XMP": {
            "dc:title": "标题(Dublin Core)",
            "dc:description": "描述(Dublin Core)",
            "dc:creator": "创建者",
            "dc:subject": "主题",
            "dc:rights": "版权信息"
        }
    }
}

def check_exiftool():
    """检查exiftool是否安装"""
    try:
        subprocess.run(["exiftool", "-ver"], 
                      capture_output=True, 
                      check=True,
                      text=True)
    except FileNotFoundError:
        logger.error("exiftool未安装或不在PATH中")
        logger.error("安装方法:")
        logger.error("Windows: 下载 https://exiftool.org/")
        logger.error("Linux: sudo apt install exiftool")
        logger.error("macOS: brew install exiftool")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        logger.error(f"exiftool检查失败: {e.stderr}")
        sys.exit(1)

def validate_image(image_path: str, format: str) -> None:
    """验证图片文件和格式"""
    format = format.upper()
    if format not in SUPPORTED_FORMATS:
        raise ValueError(f"不支持的格式: {format}")
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"文件不存在: {image_path}")
    if not os.path.isfile(image_path):
        raise ValueError(f"不是有效的文件: {image_path}")

def read_payload(payload: Optional[str], payload_file: Optional[str]) -> str:
    """从参数或文件读取payload（不做任何转义处理）"""
    if payload and payload_file:
        raise ValueError("不能同时使用--payload和--payload-file")
    if payload_file:
        if not os.path.exists(payload_file):
            raise FileNotFoundError(f"文件不存在: {payload_file}")
        with open(payload_file, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                raise ValueError("Payload文件为空")
            return content
    if payload:
        return payload
    raise ValueError("必须指定--payload或--payload-file")

def prepare_metadata_fields(format: str, meta_fields: List[str]) -> List[Tuple[str, str]]:
    """准备要插入的元数据字段"""
    format = format.upper()
    if meta_fields == ["all"]:
        return [
            (meta_type, field)
            for meta_type in SUPPORTED_FORMATS[format]
            for field in SUPPORTED_FORMATS[format][meta_type]
        ]
    
    fields = []
    for meta_field in meta_fields:
        try:
            meta_type, field = meta_field.split(".")
            meta_type = meta_type.replace("-", "")
            if meta_type not in SUPPORTED_FORMATS[format]:
                raise ValueError(f"不支持的元数据类型: {meta_type}")
            if field not in SUPPORTED_FORMATS[format][meta_type]:
                raise ValueError(f"不支持的字段: {field}")
            fields.append((meta_type, field))
        except ValueError as e:
            logger.warning(f"忽略无效字段'{meta_field}': {str(e)}")
    return fields

def execute_exiftool(cmd: List[str], context: str = "") -> None:
    """执行exiftool命令"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8',
            errors='replace'
        )
        logger.debug(f"exiftool {context}输出:\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        logger.error(f"exiftool {context}失败:\n{e.stderr}")
        raise RuntimeError(f"exiftool执行失败: {e.stderr}")

def insert_metadata(
    image_path: str,
    format: str,
    meta_fields: List[str],
    payload: str,
    output_path: Optional[str] = None
) -> None:
    """插入元数据到图片"""
    format = format.upper()
    validate_image(image_path, format)
    
    # 准备字段
    fields_to_insert = prepare_metadata_fields(format, meta_fields)
    if not fields_to_insert:
        raise ValueError("没有有效的元数据字段可插入")
    
    logger.debug(f"原始payload: {payload[:100]}...")

    # 创建临时文件
    temp_file = None
    try:
        if output_path:
            temp_dir = tempfile.gettempdir()
            temp_file = os.path.join(temp_dir, f"pixxss_temp_{os.path.basename(image_path)}")
            shutil.copy2(image_path, temp_file)
            working_path = temp_file
        else:
            working_path = image_path

        # 分组处理字段
        meta_groups = {}
        for meta_type, field in fields_to_insert:
            meta_groups.setdefault(meta_type, []).append((meta_type, field))

        # 特殊处理PNG文本块
        if format in ["PNG", "APNG"]:
            for meta_type in ["tEXt", "zTXt", "iTXt"]:
                if meta_type in meta_groups:
                    cmd = ["exiftool", "-overwrite_original", "-charset", "utf8"]
                    for _, field in meta_groups[meta_type]:
                        if meta_type == "iTXt":
                            cmd.extend([
                                f"-PNG:{field}={payload}",
                                f"-PNG:{field}:lang=en"
                            ])
                        else:
                            cmd.append(f"-PNG:{field}={payload}")
                    cmd.append(working_path)
                    execute_exiftool(cmd, f"PNG {meta_type}")

        # 处理标准元数据
        cmd = ["exiftool", "-overwrite_original", "-charset", "utf8"]
        has_standard_fields = False
        
        for meta_type, fields in meta_groups.items():
            if format in ["PNG", "APNG"] and meta_type in ["tEXt", "zTXt", "iTXt"]:
                continue
            
            for _, field in fields:
                has_standard_fields = True
                if meta_type in ["EXIF", "IPTC"]:
                    cmd.append(f"-{field}={payload}")
                elif meta_type == "XMP":
                    xmp_field = field.split(":")[1]
                    cmd.append(f"-XMP-dc:{xmp_field}={payload}")
                elif meta_type == "Comment Extension":
                    cmd.append(f"-Comment={payload}")

        if has_standard_fields:
            cmd.append(working_path)
            execute_exiftool(cmd, "标准元数据")

        # 移动最终文件
        if output_path and temp_file:
            shutil.move(temp_file, output_path)
            logger.info(f"文件已保存到: {output_path}")
        else:
            logger.info("文件已原地更新")

        # 显示最终元数据
        logger.info("\n最终文件元数据信息:")
        exif_cmd = ["exiftool", output_path or image_path]
        try:
            result = subprocess.run(
                exif_cmd,
                capture_output=True,
                text=True,
                check=True,
                encoding='utf-8',
                errors='replace'
            )
            print(result.stdout)
        except subprocess.CalledProcessError as e:
            logger.error(f"获取元数据失败: {e.stderr}")

    except Exception as e:
        logger.error(f"处理过程中出错: {str(e)}")
        if temp_file and os.path.exists(temp_file):
            os.remove(temp_file)
        raise
    finally:
        if temp_file and os.path.exists(temp_file) and (not output_path or os.path.exists(output_path)):
            os.remove(temp_file)

def display_supported_fields():
    """显示支持的字段信息"""
    output = ["支持的格式和字段:\n"]
    for fmt, meta_types in SUPPORTED_FORMATS.items():
        output.append(f"【{fmt}】")
        for meta_type, fields in meta_types.items():
            output.append(f"  {meta_type}:")
            for field in fields:
                output.append(f"    - {field}")
        output.append("")
    return "\n".join(output)

def main():
    check_exiftool()

    parser = argparse.ArgumentParser(
        description="PixXSS - 图片元数据XSS注入工具\n\n" + display_supported_fields(),
        formatter_class=CustomHelpFormatter,
        add_help=False
    )
    
    # 基本参数
    parser.add_argument("-h", "--help", action="store_true", help="显示帮助信息")
    parser.add_argument("-I", nargs="+", required=False, metavar=("FILE", "FMT"),
                       help="输入文件及格式，例如：-I image.jpg JPEG")
    
    # Payload参数组
    payload_group = parser.add_mutually_exclusive_group(required=False)
    payload_group.add_argument("-payload", help="要插入的XSS负载")
    payload_group.add_argument("--payload-file", help="从文件读取XSS负载")
    
    parser.add_argument("-o", "--output", help="输出文件路径")
    parser.add_argument("--all", action="store_true", help="插入所有支持的字段")
    
    # 动态字段参数
    field_group = parser.add_argument_group("字段选择")
    for fmt, meta_types in SUPPORTED_FORMATS.items():
        for meta_type, fields in meta_types.items():
            for field in fields:
                arg_name = f"--{fmt}-{meta_type}-{field}".replace(":", "_").replace(" ", "_").replace("/", "_")
                field_group.add_argument(arg_name, action="store_true",
                                        help=f"插入 {fmt}.{meta_type}.{field}")
    
    args = parser.parse_args()
    
    if args.help or len(sys.argv) == 1:
        print(parser.format_help())
        sys.exit(0)
    
    try:
        # 检查必要参数
        if not args.I:
            raise ValueError("必须使用-I参数指定输入文件和格式")
        if not (args.payload or args.payload_file):
            raise ValueError("必须指定--payload或--payload-file")
        
        # 读取payload（不做任何转义处理）
        payload = read_payload(args.payload, args.payload_file)
        logger.info(f"使用payload长度: {len(payload)}字符")
        
        # 处理输入文件
        file_pairs = []
        input_args = args.I
        while len(input_args) >= 2:
            file_pairs.append((input_args[0], input_args[1].upper()))
            input_args = input_args[2:]
        
        if not file_pairs:
            raise ValueError("必须提供至少一个文件路径和格式")
        
        # 收集字段
        meta_fields = []
        if args.all:
            meta_fields = ["all"]
            logger.info("将插入所有支持的元数据字段")
        else:
            for fmt in SUPPORTED_FORMATS:
                for meta_type, fields in SUPPORTED_FORMATS[fmt].items():
                    for field in fields:
                        arg_name = f"{fmt}_{meta_type}_{field}".replace(":", "_").replace(" ", "_").replace("-", "_").replace("/", "_")
                        if getattr(args, arg_name, False):
                            meta_fields.append(f"{meta_type}.{field}")
            
            if not meta_fields:
                raise ValueError("未选择任何元数据字段，请使用--all或指定字段")
        
        # 处理每个文件
        for input_file, fmt in file_pairs:
            try:
                logger.info(f"处理文件: {input_file} ({fmt})")
                
                output_file = args.output
                if args.output and len(file_pairs) > 1:
                    base_name = os.path.basename(input_file)
                    output_file = os.path.join(os.path.dirname(args.output), f"mod_{base_name}")
                
                insert_metadata(
                    image_path=input_file,
                    format=fmt,
                    meta_fields=meta_fields,
                    payload=payload,
                    output_path=output_file
                )
                
            except Exception as e:
                logger.error(f"处理 {input_file} 失败: {str(e)}")
                continue
    
    except Exception as e:
        logger.error(f"程序运行失败: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("操作被用户中断")
        sys.exit(130)
    except Exception as e:
        logger.error(f"致命错误: {str(e)}")
        sys.exit(1)