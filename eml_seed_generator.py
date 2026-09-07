#!/usr/bin/env python3
"""
Enhanced EML (Email Message) Seed Generator using LLM
基于LLM的增强型EML邮件内容种子生成器
"""

import os
import json
import argparse
from openai import OpenAI  # 需要安装openai包: pip install openai

# 配置信息
# 注意: 不要硬编码 API key。旧 key 已泄露(进过公开 git 历史), 请在服务商处吊销并轮换。
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
MODEL_NAME = "deepseek-chat"  
SEED_CORPUS_DIR = "seed_corpus"

def generate_email_content_with_llm(prompt_description):
    """使用大模型生成邮件内容"""
    
    client = OpenAI(api_key=OPENAI_API_KEY, base_url="https://api.deepseek.com/v1")
    
    # 精心设计的提示词 - 核心逻辑
    system_prompt = """
    你是一个高级电子邮件内容生成引擎，专门用于创建各种类型的电子邮件内容，用于模糊测试邮件服务器和客户端。
    请根据用户提供的描述，生成符合要求的电子邮件内容（EML格式）。
    
    输出必须是严格的JSON格式，包含以下字段：
    - subject: 邮件主题
    - from: 发件人地址
    - to: 收件人地址
    - cc: 抄送地址 (可选)
    - bcc: 密送地址 (可选)
    - headers: 额外的邮件头部信息 (可选)
    - body_text: 纯文本邮件正文
    - body_html: HTML格式邮件正文 (可选)
    - attachments: 附件信息列表，每个附件包含:
        filename: 附件文件名
        content_type: MIME类型
        content: 附件内容 (可以是文本或Base64编码的二进制数据)
        
    生成的内容应该:
    1. 语法正确，符合RFC 2822标准
    2. 包含各种边界情况和潜在的恶意内容，用于测试邮件解析器的健壮性
    3. 可以包含超长字段、特殊字符、非ASCII字符、HTML/JS代码等
    4. 可以模拟真实的邮件结构，包括多部分MIME消息
    """
    
    user_prompt = f"""
    请生成一个用于模糊测试的电子邮件内容，描述如下：
    
    {prompt_description}
    
    请确保生成的内容具有潜在的测试价值，能够覆盖各种边界情况。
    """
    
    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.8,  # 增加随机性以生成更多样化的测试用例
            max_tokens=4000,
            response_format={"type": "json_object"}
        )
        
        result = response.choices[0].message.content
        return json.loads(result)
    except Exception as e:
        print(f"[-] LLM生成失败: {str(e)}")
        return None

def create_eml_content(email_data):
    """根据生成的数据创建EML格式的邮件内容"""
    
    # 构建邮件头部
    headers = []
    headers.append(f"From: {email_data.get('from', 'test@example.com')}")
    headers.append(f"To: {email_data.get('to', 'user@example.com')}")
    
    cc = email_data.get('cc')
    if cc:
        headers.append(f"Cc: {cc}")
        
    bcc = email_data.get('bcc')
    if bcc:
        headers.append(f"Bcc: {bcc}")
        
    headers.append(f"Subject: {email_data.get('subject', 'Test Email')}")
    
    # 添加额外头部
    extra_headers = email_data.get('headers', {})
    for key, value in extra_headers.items():
        headers.append(f"{key}: {value}")
        
    # 添加日期头部
    from datetime import datetime
    headers.append(f"Date: {datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')}")
    
    # 构建邮件正文和附件
    body_text = email_data.get('body_text', '')
    body_html = email_data.get('body_html', '')
    attachments = email_data.get('attachments', [])
    
    if not attachments and not body_html:
        # 简单的纯文本邮件
        headers.append("Content-Type: text/plain; charset=utf-8")
        headers.append("Content-Transfer-Encoding: 8bit")
        eml_content = "\r\n".join(headers) + "\r\n\r\n" + body_text
    else:
        # 多部分MIME邮件
        import random
        import string
        boundary = "----=_NextPart_" + ''.join(random.choices(string.ascii_letters + string.digits, k=20))
        headers.append(f"Content-Type: multipart/mixed; boundary=\"{boundary}\"")
        
        eml_content = "\r\n".join(headers) + "\r\n\r\n"
        
        # 纯文本部分
        if body_text:
            eml_content += f"--{boundary}\r\n"
            eml_content += "Content-Type: text/plain; charset=utf-8\r\n"
            eml_content += "Content-Transfer-Encoding: 8bit\r\n\r\n"
            eml_content += body_text + "\r\n"
            
        # HTML部分
        if body_html:
            eml_content += f"--{boundary}\r\n"
            eml_content += "Content-Type: text/html; charset=utf-8\r\n"
            eml_content += "Content-Transfer-Encoding: 8bit\r\n\r\n"
            eml_content += body_html + "\r\n"
            
        # 附件部分
        for attachment in attachments:
            eml_content += f"--{boundary}\r\n"
            eml_content += f"Content-Type: {attachment.get('content_type', 'application/octet-stream')}\r\n"
            eml_content += f"Content-Transfer-Encoding: base64\r\n"
            eml_content += f"Content-Disposition: attachment; filename=\"{attachment.get('filename', 'attachment.txt')}\"\r\n\r\n"
            eml_content += attachment.get('content', '') + "\r\n"
            
        # 结束边界
        eml_content += f"--{boundary}--\r\n"
        
    return eml_content

def save_seed_corpus(program_name, seeds):
    """保存种子到语料库目录"""
    os.makedirs(SEED_CORPUS_DIR, exist_ok=True)
    corpus_dir = os.path.join(SEED_CORPUS_DIR, program_name)
    os.makedirs(corpus_dir, exist_ok=True)
    
    for i, seed in enumerate(seeds):
        # 保存EML文件
        eml_filename = os.path.join(corpus_dir, f"seed_{i+1:04d}.eml")
        # newline="" 防止 Windows 文本模式把内容里的 \r\n 二次转换成 \r\r\n
        with open(eml_filename, "w", encoding="utf-8", newline="") as f:
            f.write(seed)
            
    print(f"[+] 生成 {len(seeds)} 个EML种子到目录: {corpus_dir}")
    return corpus_dir

def main():
    parser = argparse.ArgumentParser(description="基于LLM的EML邮件内容种子生成器")
    parser.add_argument("--description", default="生成一个包含各种边界情况的测试邮件", help="邮件内容描述")
    parser.add_argument("--count", type=int, default=5, help="生成种子的数量")
    parser.add_argument("--program", default="email_fuzzer", help="程序名称，用于创建子目录")
    args = parser.parse_args()
    
    if not OPENAI_API_KEY:
        print("[-] 错误: 未设置 OPENAI_API_KEY 环境变量")
        print("    用法(Windows): set OPENAI_API_KEY=sk-xxx")
        print("    用法(Linux/macOS): export OPENAI_API_KEY=sk-xxx")
        return
    
    print("[*] 使用LLM生成EML邮件内容种子...")
    
    seeds = []
    for i in range(args.count):
        print(f"[*] 生成第 {i+1}/{args.count} 个种子...")
        email_data = generate_email_content_with_llm(args.description)
        
        if not email_data:
            print(f"[-] LLM生成失败，跳过种子 {i+1}")
            continue
            
        if not isinstance(email_data, dict):
            print(f"[-] LLM 返回结果不是 JSON 对象，跳过种子 {i+1}")
            continue
        
        try:
            eml_content = create_eml_content(email_data)
            seeds.append(eml_content)
            print(f"[+] 成功生成种子 {i+1}")
        except Exception as e:
            print(f"[-] 创建EML内容失败: {str(e)}")
            
    if seeds:
        # 保存种子语料库
        corpus_dir = save_seed_corpus(args.program, seeds)
        print("\n[+] 操作完成!")
        print(f"    语料库  : {corpus_dir}")
        print("\n下一步: 使用生成的EML文件作为种子进行邮件服务器/客户端的模糊测试")
    else:
        print("\n[-] 未能生成任何有效的种子")

if __name__ == "__main__":
    main()