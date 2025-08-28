#!/usr/bin/env python3

"""
CVE-XXXX-YYYY POP3 Fuzz Mail Generator (Boofuzz EML Fuzzing Version)

根据 CVE-XXXX-YYYY_POP3_Header_Risks.md 和 poc.md 的分析，
使用 Boofuzz 库生成用于 fuzz 测试 libcurl POP3 客户端漏洞的 .eml 邮件文件。

此脚本创建一个 Boofuzz Session，针对 .eml 文件的内容进行 fuzzing，并将每个变异
保存为一个单独的 .eml 文件。这利用了 Boofuzz 的完整 fuzzing 能力。

目标：
1.  验证邮件头 (Header) 中的点号转义处理缺失 (Dot-Unstuffing Failure)。
2.  验证邮件头 (Header) 中的 EOB 部分匹配失败导致的数据写入错误。
3.  探索利用这两个漏洞作为“操作原语”进行组合利用的可能性，
    特别是在邮件头区域制造混乱或误导性信息。
4.  生成大量具有高度变异的 .eml 文件，用于广泛的 fuzzing 测试。
"""

import sys
import os
import random
import string
from datetime import datetime

# 将 boofuzz 添加到 Python 路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

import boofuzz as bf


# --- 配置 ---

# 默认输出目录
DEFAULT_OUTPUT_DIR = "fuzzed_pop3_mails"

# Boofuzz Request 名称
REQUEST_NAME = "pop3_fuzz_mail"

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


def generate_random_string(length=10):
    """生成指定长度的随机字符串。"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def generate_special_random_string(length=10):
    """
    生成包含特殊字符的指定长度的随机字符串。
    包括控制字符、非ASCII字符和常见特殊符号，以增加 fuzzing 的多样性。
    """
    # 定义字符集：ASCII字母数字 + 常见特殊符号 + 一些控制字符和非ASCII字符
    # 注意：避免在关键分隔符位置使用 \r, \n, \x00 可能会破坏邮件结构
    # 这里主要用于头部值和体部内容的 fuzzing
    chars = (
        string.ascii_letters + 
        string.digits + 
        "!@#$%^&*()_+-=[]{}|;':\",./<>?" + # 常见符号
        "\t\x01\x02\x1b\x7f" +             # 控制字符示例 (不含 \r, \n, \x00)
        "\u202e\u202d"                     # Unicode 控制字符 (RTL override, LTR override)
    )
    return ''.join(random.choices(chars, k=length))


def create_fuzz_request():
    """
    使用 Boofuzz 原语创建一个可 fuzz 的 POP3 邮件请求。
    这个请求定义了邮件的结构和哪些部分可以被 fuzz。
    """
    print(f"[*] Initializing Boofuzz request '{REQUEST_NAME}' for fuzzing...")

    # 初始化一个新的 Boofuzz 请求
    if REQUEST_NAME in bf.blocks.REQUESTS:
        del bf.blocks.REQUESTS[REQUEST_NAME]
    bf.s_initialize(REQUEST_NAME)

    # --- 邮件头部部分 ---
    # 使用 `s_string` 和 `s_static` 来定义可 fuzz 和静态的部分
    bf.s_static("From: ")
    # 在发件人中引入特殊字符 fuzz
    bf.s_string(f'sender_{generate_random_string(5)}@example.com', name="from_header_value")
    # 可选：增加一个使用特殊字符的变体 fuzz 点
    # bf.s_string(f'sender_{generate_special_random_string(5)}@example.com', name="from_header_value_special")
    bf.s_static("\\r\\n")

    bf.s_static("To: ")
    # 在收件人中也引入特殊字符 fuzz
    bf.s_string(f'recipient_{generate_random_string(5)}@example.com', name="to_header_value")
    # 可选：增加一个使用特殊字符的变体 fuzz 点
    # bf.s_string(f'recipient_{generate_special_random_string(5)}@example.com', name="to_header_value_special")
    bf.s_static("\\r\\n")

    bf.s_static("Subject: Fuzz Test for CVE-XXXX-YYYY - ")
    # 在主题中引入特殊字符 fuzz
    bf.s_string(generate_random_string(10), name="subject_random_part")
    # 增加一个使用特殊字符的 fuzz 点
    bf.s_string(generate_special_random_string(10), name="subject_special_random_part")
    bf.s_static("\\r\\n")

    bf.s_static("Date: Mon, 01 Jan 2024 12:00:00 +0000\\r\\n")
    bf.s_static("MIME-Version: 1.0\\r\\n")
    bf.s_static("Content-Type: text/plain; charset=utf-8\\r\\n")

    bf.s_static("X-Normal-Header: For comparison - ")
    # 在普通头部值中引入特殊字符 fuzz
    bf.s_string(generate_random_string(15), name="normal_header_value")
    # 增加一个使用特殊字符的 fuzz 点
    bf.s_string(generate_special_random_string(15), name="normal_header_value_special")
    bf.s_static("\\r\\n")

    # --- 添加专门用于触发漏洞的头部 ---
    # 使用 `s_static` 定义核心模式，因为这些是精确触发漏洞的关键部分。
    # 我们也可以使用 `s_string` 或 `s_group` 来对这些模式的某些部分进行 fuzz。
    bf.s_static(f"X-Original-Header-Dot: {HEADER_DOT_PATTERN}\\r\\n")

    bf.s_static("X-EOB-Test-Header: ")
    bf.s_static(HEADER_EOB_PATTERN_PREFIX)
    bf.s_static(" ")
    # 在 EOB 测试头部的随机部分引入特殊字符 fuzz
    bf.s_string(generate_random_string(10), name="eob_header_random_part")
    # 增加一个使用特殊字符的 fuzz 点
    bf.s_string(generate_special_random_string(10), name="eob_header_random_part_special")
    bf.s_static("\\r\\n")
    
    # --- 头部破坏触发点 ---
    # 利用 B 漏洞在头部注入 `\r\n.`，尝试干扰头部解析
    # 这个注入可能会让解析器认为头部在此处结束
    bf.s_static("X-Header-Truncator: ..BoomHeader ")
    # 在头部破坏触发点的随机部分引入特殊字符 fuzz
    bf.s_string(generate_random_string(7), name="header_boom_random")
    # 增加一个使用特殊字符的 fuzz 点
    bf.s_string(generate_special_random_string(7), name="header_boom_random_special")
    bf.s_static("\\r\\n")

    # 增加更多可 fuzz 的头部，以增加复杂性
    bf.s_static("X-Another-Dot-Header: ")
    bf.s_string(".Another dot test line.", name="another_dot_header_value")
    bf.s_static("\\r\\n")

    bf.s_static("X-Another-EOB-Header: ")
    bf.s_static("..AnotherEOBTriggerZ ")
    bf.s_string(generate_random_string(8), name="eob_header_random_part2")
    bf.s_static("\\r\\n")

    # 使用 Group 来 fuzz 一些常见的头部名
    header_names = ["X-Custom-Fuzz1", "X-Custom-Fuzz2", "X-Custom-Fuzz3", "X-Powered-By", "X-Version", "MIME-Version", "Content-Type", "Content-Transfer-Encoding"]
    bf.s_group("custom_header_names", values=header_names)
    bf.s_static(": ")
    # 在自定义头部值中引入特殊字符 fuzz
    bf.s_string("Some fuzzable value ", name="fuzzable_header_value")
    bf.s_string(generate_random_string(5), name="fuzzable_header_random_tail")
    # 增加一个使用特殊字符的 fuzz 点
    bf.s_string(generate_special_random_string(5), name="fuzzable_header_random_tail_special")
    bf.s_static("\r\n")

    # --- 增加 MIME 相关头部 fuzz ---
    mime_types = ["text/plain", "text/html", "multipart/mixed", "multipart/alternative"]
    bf.s_static("Content-Type: ")
    bf.s_group("content_types", values=mime_types)
    bf.s_static("; charset=")
    bf.s_string("utf-8", name="charset_value")
    bf.s_static("\r\n")

    encoding_types = ["7bit", "8bit", "base64", "quoted-printable"]
    bf.s_static("Content-Transfer-Encoding: ")
    bf.s_group("transfer_encodings", values=encoding_types)
    bf.s_static("\r\n")

    # --- 邮件头部与体部的分隔符 ---
    bf.s_static("\\r\\n") # This signifies the end of headers

    # --- 邮件体部部分 ---
    # 体部也可以被高度 fuzz
    bf.s_static("This is the body of the fuzz test email.\r\n\r\n")

    # 点号转义处理缺失 (Dot-Unstuffing Failure)
    bf.s_static(BODY_DOT_PATTERN)
    bf.s_static("\r\n")

    # 添加一行以 .. 开头的内容（原始内容）。
    bf.s_static("..This line starts with two dots (original content).\r\n\r\n")

    bf.s_static("More normal body content.\r\n\r\n")

    # EOB 部分匹配失败 (Incorrect Data Write on EOB Partial Match Failure)
    # --- 简单触发点 ---
    bf.s_static(BODY_EOB_PATTERN_PREFIX)
    # 在 EOB 测试体部的随机部分引入特殊字符 fuzz
    bf.s_string(generate_random_string(5), name="eob_body_random_part")
    # 增加一个使用特殊字符的 fuzz 点
    bf.s_string(generate_special_random_string(5), name="eob_body_random_part_special")
    bf.s_static("\r\n")
    bf.s_static("Line after the line that triggers the EOB bug in the body.\r\n\r\n")
    
    # --- 链式反应触发点 1 ---
    # 构造一个能够通过 B 漏洞注入 `\r\n.` 的模式
    # 注入的 `\r\n.` 会将下一行提升，模拟结构改变
    bf.s_static("Line before chained reaction trigger.\r\n")
    bf.s_static("..ChainedReactionTrigger ")
    # 在链式反应触发点1的随机部分引入特殊字符 fuzz
    bf.s_string(generate_random_string(8), name="chain_react_1_random")
    # 增加一个使用特殊字符的 fuzz 点
    bf.s_string(generate_special_random_string(8), name="chain_react_1_random_special")
    bf.s_static("\r\n")
    # 下一行在被注入的 `\r\n.` 提升后，可能被解析为头部
    bf.s_static("X-Injected-Header-From-Chain: This line might be seen as a header after B-injection.\r\n")
    bf.s_static("\r\n")

    # --- 链式反应触发点 2 ---
    # 更复杂的模式，模拟多级注入
    bf.s_static("Another line before a complex chained reaction.\r\n")
    bf.s_static("..ComplexChain ")
    # 在链式反应触发点2的随机部分引入特殊字符 fuzz
    bf.s_string(generate_random_string(6), name="chain_react_2_random_a")
    # 增加一个使用特殊字符的 fuzz 点
    bf.s_string(generate_special_random_string(6), name="chain_react_2_random_a_special")
    bf.s_static(" ")
    bf.s_string(generate_random_string(4), name="chain_react_2_random_b")
    # 增加一个使用特殊字符的 fuzz 点
    bf.s_string(generate_special_random_string(4), name="chain_react_2_random_b_special")
    bf.s_static("\r\n")
    # 这个注入可能会进一步影响数据流
    bf.s_static("Content that follows the complex chain reaction trigger.\r\n\r\n")

    # 使用 s_random 添加一大块随机内容以增加 fuzzing 的覆盖面
    bf.s_random("", min_length=50, max_length=500, num_mutations=50, name="large_random_body_block")
    # 可选：增加一个包含特殊字符的随机块
    # bf.s_random("", min_length=50, max_length=500, num_mutations=50, name="large_random_body_block_with_special_chars", 
    #            fuzz_values=string.ascii_letters + string.digits + "\x00\x01\x02\x1b\x7f\u202e\u202d!@#$%^&*()_+-=[]{}|;':",./<>?")
    bf.s_static("\r\n\r\n")

    bf.s_static("End of the email body.\r\n")

    # POP3 EOB (End of Body marker) - 通常保持静态
    bf.s_static(".\\r\\n")

    print(f"[+] Boofuzz request '{REQUEST_NAME}' successfully initialized for fuzzing.")
    return bf.s_get(REQUEST_NAME)


class EMLFileLogger(bf.IFuzzLogger):
    """
    自定义 Boofuzz Logger，用于将每个 fuzz 测试用例保存为一个 .eml 文件。
    """
    def __init__(self, output_dir=DEFAULT_OUTPUT_DIR):
        self.output_dir = output_dir
        self.test_case_count = 0
        # 确保输出目录存在
        os.makedirs(self.output_dir, exist_ok=True)

    def open_test_case(self, test_case_id, name, index, *args, **kwargs):
        """
        当一个新的测试用例开始时调用。
        我们在这里准备文件名。
        """
        self.test_case_count = index
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.current_filename = os.path.join(
            self.output_dir, f"test_case_{index:05d}_{timestamp}.eml"
        )
        print(f"[*] Preparing test case {index} -> {self.current_filename}")

    def open_test_step(self, description): pass
    def log_check(self, description): pass
    def log_error(self, description): pass
    def log_recv(self, data): pass
    def log_info(self, description): pass
    def close_test_case(self): pass
    # 实现抽象方法
    def log_pass(self, description=""): pass
    def log_fail(self, description="", reason=""): pass

    def log_send(self, data):
        """
        当 Boofuzz 发送（或在这种情况下，渲染）数据时调用。
        我们将渲染后的数据保存到 .eml 文件中。
        """
        try:
            # `data` 是 bytes 类型，直接写入文件
            with open(self.current_filename, 'wb') as f:
                f.write(data)
            print(f"[+] Saved fuzzed email to '{self.current_filename}'")
        except Exception as e:
            print(f"[-] Failed to save email to '{self.current_filename}': {e}")

    def close_test(self):
        """当整个 fuzzing session 结束时调用。"""
        print(f"[#] Fuzzing session finished. Generated {self.test_case_count} test cases in '{self.output_dir}'.")


def main():
    """主函数，设置 fuzzing session 并运行。"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate fuzzed POP3 .eml files for CVE-XXXX-YYYY using Boofuzz."
    )
    parser.add_argument(
        "-o", "--output-dir", default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory for fuzzed .eml files (default: {DEFAULT_OUTPUT_DIR})"
    )
    parser.add_argument(
        "-n", "--num-tests", type=int, default=100,
        help="Number of fuzz test cases to generate (default: 100)"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show the request structure and number of mutations without generating files."
    )

    args = parser.parse_args()

    # 1. 创建 fuzzing 请求
    request = create_fuzz_request()

    if args.dry_run:
        print("[*] Dry run mode: Showing request info...")
        print(f"Request Name: {request.name}")
        print(f"Total mutations available: {request.num_mutations()}")
        print("--- Request Blocks/Primitives ---")
        for item in request.walk():
            if hasattr(item, 'name') and item.name:
                fuzzability = "Fuzzable" if getattr(item, 'fuzzable', False) else "Static"
                print(f"  - {item.name} ({type(item).__name__}, {fuzzability})")
        print("--------------------------------")
        print("[*] Dry run complete.")
        return

    # 2. 设置自定义 logger
    eml_logger = EMLFileLogger(output_dir=args.output_dir)

    # 3. 创建一个虚拟的 Session
    # 我们不连接到任何目标，只是利用 Session 的 fuzzing 和 logging 机制。
    # 使用一个不执行任何操作的 DummyConnection。
    class DummyConnection(bf.ITargetConnection):
        def __init__(self): pass
        def close(self): pass
        def open(self): pass
        def recv(self, max_bytes): return b""
        def send(self, data): pass # 丢弃数据
        def info(self): return "Dummy Connection for EML Generation" # 实现 info 方法

    target = bf.Target(connection=DummyConnection())
    
    # 创建 Session，禁用网络相关检查，因为我们只是生成文件
    session = bf.Session(
        target=target,
        fuzz_loggers=[eml_logger],
        receive_data_after_each_request=False,
        check_data_received_each_request=False,
        receive_data_after_fuzz=False,
        # 可以通过这个参数限制生成的测试用例数量
        # 但我们将在循环中手动控制
    )

    # 4. 将请求连接到 session
    session.connect(request)

    # 5. 运行 fuzzing
    # 使用 Session 的构造函数参数来限制测试用例数量，这是推荐的方式
    # 并禁用 web_server 以避免事件循环问题和不必要的交互
    print(f"[*] Starting fuzzing session to generate {args.num_tests} .eml files...")
    print(f"[*] Output directory: {args.output_dir}")
    print("[*] This may take a while depending on the number of tests and their complexity.")
    
    # 重新创建 session，使用 index 参数控制范围，并禁用 web_server
    session = bf.Session(
        target=target,
        fuzz_loggers=[eml_logger],
        receive_data_after_each_request=False,
        check_data_received_each_request=False,
        receive_data_after_fuzz=False,
        # 从第1个case开始
        index_start=1,
        # 运行到第args.num_tests个case或请求的总mutation数，取较小值
        index_end=min(args.num_tests, request.num_mutations()),
        # 禁用web界面以避免事件循环冲突
        web_port=None 
    )
    session.connect(request)
    
    try:
        # 现在直接调用 fuzz()，它会根据 index_start 和 index_end 运行
        session.fuzz()
            
    except KeyboardInterrupt:
        print("\\n[!] Fuzzing interrupted by user.")
    except Exception as e:
        print(f"\\n[!] An error occurred during fuzzing: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print(f"[#] Fuzzing session finished. Check '{args.output_dir}' for output files.")


if __name__ == '__main__':
    main()


if __name__ == '__main__':
    main()