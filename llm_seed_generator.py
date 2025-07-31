import os
import json
import re
import subprocess
import argparse
from openai import OpenAI  # 需要安装openai包: pip install openai

# 配置信息 
OPENAI_API_KEY = "sk-685d222ccd554507a72f36cd0908902f"
MODEL_NAME = "deepseek-chat"  
MAN_PAGE_DIR = "man_pages"
SEED_CORPUS_DIR = "seed_corpus"

def extract_man_page(program_name):
    """提取程序的man文档内容"""
    os.makedirs(MAN_PAGE_DIR, exist_ok=True)
    output_file = os.path.join(MAN_PAGE_DIR, f"{program_name}.txt")
    
    try:
        # 尝试获取man文档
        with open(output_file, "w", encoding="utf-8") as f:
            subprocess.run(["man", program_name], stdout=f, stderr=subprocess.DEVNULL, check=True)
        print(f"[+] 成功提取 {program_name} 的man文档")
        return output_file
    except (subprocess.CalledProcessError, FileNotFoundError):
        # 如果man命令失败，尝试使用--help作为备选
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                result = subprocess.run([program_name, "--help"], 
                                      stdout=f, stderr=subprocess.STDOUT, 
                                      text=True, check=True)
            print(f"[!] 使用 --help 替代man文档: {program_name}")
            return output_file
        except Exception as e:
            print(f"[-] 错误: 无法获取 {program_name} 的文档 - {str(e)}")
            return None

def analyze_man_page_with_llm(man_file_path):
    """使用大模型分析man文档并提取参数信息"""
    with open(man_file_path, "r", encoding="utf-8", errors="ignore") as f:
        man_content = f.read()
    
    # 如果文档太长进行截断 (根据模型上下文长度调整)
    if len(man_content) > 120000:
        man_content = man_content[:60000] + "\n[...TRUNCATED...]\n" + man_content[-60000:]
    
    client = OpenAI(api_key=OPENAI_API_KEY, base_url="https://api.deepseek.com")
    
    # 精心设计的提示词 - 核心逻辑
    system_prompt = """
    你是一个高级程序分析引擎，专门用于解析UNIX/Linux手册页(man pages)。
    请严格分析提供的man文档内容，提取所有命令行参数/选项的详细信息。
    输出必须是严格的JSON格式，包含以下字段：
    
    - program_name: 程序名称
    - parameters: 参数列表，每个参数包含：
        option: 参数选项形式 (如 "-f, --file")
        type: 推断的类型 (string, integer, float, boolean, enum, path, url, ip等)
        is_required: 是否必需 (true/false)
        description: 功能简述
        constraints: 约束条件列表
        examples: 取值示例列表
        dangerous_flags: 是否高危 (如 -r, -f, --no-preserve-root等)
    
    类型推断规则：
    - string: 文本、文件名、路径、URL、正则表达式
    - integer/float: 数值、端口号、大小限制 (注意范围)
    - boolean: 标志型选项 (存在/不存在)
    - enum: 有限取值 (如 --color={always,never,auto})
    - special: 时间格式、日期、IP地址等
    
    对于模糊的描述，标注为 'unknown' 并记录原文。
    注意平台差异 (Linux vs BSD)。
    """
    
    user_prompt = f"""
    请解析以下man文档内容：
    
    {man_content}
    """
    
    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1,
            max_tokens=4000,
            response_format={"type": "json_object"}
        )
        
        result = response.choices[0].message.content
        return json.loads(result)
    except Exception as e:
        print(f"[-] LLM分析失败: {str(e)}")
        return None

def generate_fuzz_seeds(parameters):
    """基于参数信息生成模糊测试种子"""
    seeds = {"seeds": []}
    
    for param in parameters:
        option = param.get("option", "")
        param_type = param.get("type", "unknown").lower()
        examples = param.get("examples", [])
        constraints = param.get("constraints", [])
        is_dangerous = param.get("dangerous_flags", False)
        
        # 基本清理选项格式
        option = re.split(r'[,\s]+', option)[0]  # 取第一个选项形式
        
        # 为不同类型的参数生成种子
        param_seeds = []
        
        # 1. 添加合法示例值
        for ex in examples:
            if ex:  # 跳过空示例
                param_seeds.append({
                    "value": ex,
                    "reason": "合法示例值"
                })
        
        # 2. 根据参数类型生成边界值
        if "int" in param_type or "port" in param_type:
            param_seeds.extend([
                {"value": "0", "reason": "零值"},
                {"value": "-1", "reason": "负值"},
                {"value": "2147483647", "reason": "INT_MAX"},
                {"value": "-2147483648", "reason": "INT_MIN"},
                {"value": "9999999999", "reason": "超大整数"}
            ])
        elif "float" in param_type:
            param_seeds.extend([
                {"value": "0.0", "reason": "零值"},
                {"value": "-0.0", "reason": "负零"},
                {"value": "NaN", "reason": "非数字"},
                {"value": "Infinity", "reason": "无穷大"},
                {"value": "-Infinity", "reason": "负无穷大"},
                {"value": "1e-300", "reason": "极小值"},
                {"value": "1e300", "reason": "极大值"}
            ])
        elif "bool" in param_type:
            # 布尔值不需要额外值
            param_seeds.append({
                "value": "",
                "reason": "布尔标志"
            })
        else:  # 字符串和其他类型
            param_seeds.extend([
                {"value": "A" * 10000, "reason": "超长字符串"},
                {"value": "../../etc/passwd", "reason": "路径遍历"},
                {"value": "file; rm -rf /tmp/111", "reason": "命令注入尝试"},
                {"value": "http://<script>alert(1)</script>", "reason": "XSS尝试"},
                {"value": "%n%n%n%n", "reason": "格式化字符串攻击"},
                {"value": "\\x00\\x01\\x02\\x03", "reason": "二进制数据"}
            ])
            
            # 针对特定类型的额外测试
            if "path" in param_type or "file" in param_type:
                param_seeds.extend([
                    {"value": "/dev/null", "reason": "设备文件"},
                    {"value": "/" * 100, "reason": "超长路径"}
                ])
            if "url" in param_type:
                param_seeds.extend([
                    {"value": "javascript:alert(1)", "reason": "危险协议"},
                    {"value": "http://" + "A"*500, "reason": "超长URL"}
                ])
            if "ip" in param_type:
                param_seeds.extend([
                    {"value": "127.0.0.1", "reason": "环回地址"},
                    {"value": "999.999.999.999", "reason": "无效IP"},
                    {"value": "::1", "reason": "IPv6地址"}
                ])
        
        # 3. 添加约束违反测试
        for constraint in constraints:
            if "必须存在" in constraint or "required" in constraint.lower():
                param_seeds.append({
                    "value": "/non/existent/path",
                    "reason": "违反约束: 文件不存在"
                })
            if "大于" in constraint or ">" in constraint:
                match = re.search(r'大于 (\d+)', constraint)
                if match:
                    num = int(match.group(1)) - 1
                    param_seeds.append({
                        "value": str(num),
                        "reason": f"违反约束: 小于 {match.group(1)}"
                    })
        
        # 4. 高危参数的额外测试
        if is_dangerous:
            param_seeds.extend([
                {"value": "| rm -rf /", "reason": "高危命令注入"},
                {"value": "$(reboot)", "reason": "高危命令替换"},
                {"value": "a"*1000000, "reason": "超大输入测试"}
            ])
        
        seeds["seeds"].append({
            "option": option,
            "values": param_seeds
        })
    
    return seeds

def save_seed_corpus(program_name, seeds):
    """保存种子到语料库目录"""
    os.makedirs(SEED_CORPUS_DIR, exist_ok=True)
    corpus_dir = os.path.join(SEED_CORPUS_DIR, program_name)
    os.makedirs(corpus_dir, exist_ok=True)
    
    seed_index = 1
    for param in seeds["seeds"]:
        option = param["option"]
        
        for value_info in param["values"]:
            value = value_info["value"]
            
            # 构建命令行
            if "bool" in value_info["reason"].lower() or not value:
                command = f"{option}"
            else:
                # 处理包含空格的值
                if " " in value and not value.startswith(('"', "'")):
                    command = f"{option} \"{value}\""
                else:
                    command = f"{option} {value}"
            
            # 保存种子文件
            filename = os.path.join(corpus_dir, f"seed_{seed_index:04d}")
            with open(filename, "w", encoding="utf-8") as f:
                f.write(command)
            
            seed_index += 1
    
    print(f"[+] 生成 {seed_index-1} 个种子到目录: {corpus_dir}")
    return corpus_dir

def main():
    parser = argparse.ArgumentParser(description="基于man文档的模糊测试种子生成器")
    parser.add_argument("program", help="要分析的程序名称")
    parser.add_argument("--local-llm", help="本地LLM API端点 (如 http://localhost:8000/v1)")
    args = parser.parse_args()
    
    # 步骤1: 提取man文档
    man_file = extract_man_page(args.program)
    if not man_file:
        return
    
    # 步骤2: 使用LLM分析man文档
    print("[*] 使用LLM分析man文档...")
    param_info = analyze_man_page_with_llm(man_file)
    
    if not param_info:
        print("[-] 无法分析参数信息")
        return
    
    # 保存参数信息用于调试
    param_file = os.path.join(MAN_PAGE_DIR, f"{args.program}_params.json")
    with open(param_file, "w", encoding="utf-8") as f:
        json.dump(param_info, f, indent=2)
    print(f"[+] 参数分析结果保存到: {param_file}")
    
    # 步骤3: 生成模糊测试种子
    print("[*] 生成模糊测试种子...")
    seeds = generate_fuzz_seeds(param_info["parameters"])
    
    # 保存种子信息
    seed_info_file = os.path.join(SEED_CORPUS_DIR, f"{args.program}_seeds.json")
    with open(seed_info_file, "w", encoding="utf-8") as f:
        json.dump(seeds, f, indent=2)
    
    # 步骤4: 创建种子语料库
    corpus_dir = save_seed_corpus(args.program, seeds)
    
    print("\n[+] 操作完成!")
    print(f"    参数分析: {param_file}")
    print(f"    种子信息: {seed_info_file}")
    print(f"    语料库  : {corpus_dir}")
    print("\n下一步: 使用模糊测试工具如AFL++或libFuzzer进行测试")
    print(f"示例: afl-fuzz -i {corpus_dir} -o findings -- ./{args.program} @@")

if __name__ == "__main__":
    main()