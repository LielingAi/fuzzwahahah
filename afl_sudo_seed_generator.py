"""
AFL++ Sudo 种子生成器
结合 FuzzWahahah 的 AI 增强功能为 AFL++ 生成 sudo 测试种子
"""

import os
import sys
import argparse
import random
import string
from pathlib import Path
from typing import List, Dict, Any

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

#try:
from boofuzz.utils.enhanced_symbolic_execution import generate_protocol_data,learn_from_test_result,\
                                                        save_ai_learning_data, grenerate_ai_enhanced_data, \
                                                        load_protocol_ai_data,generate_binary_data
# from boofuzz.utils.enhanced_symbolic_execution import generate_binary_data
ENHANCED_MODE = True
print("✅ 已启用 FuzzWahahah AI 增强模式")
#except ImportError:
#    ENHANCED_MODE = False
#    print("⚠️  FuzzWahahah 增强功能不可用，使用基础模式")

class AFLSudoSeedGenerator:
    """AFL++ Sudo 种子生成器"""
    
    def __init__(self, output_dir="afl_sudo_seeds"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.seed_count = 0
        
        # 基础 sudo 选项和命令
        self.base_sudo_options = [
            "h", "help", "V", "version", "l", "list", "v", "validate",
            "k", "kill", "K", "remove-timestamp", "s", "shell", "i", "login",
            "b", "background", "e", "edit", "u", "user", "g", "group",
            "H", "set-home", "P", "preserve-groups", "E", "preserve-env",
            "n", "non-interactive", "S", "stdin", "A", "askpass"
        ]
        
        self.base_commands = [
            "/bin/ls", "/bin/cat", "/bin/echo", "/usr/bin/id", "/usr/bin/whoami",
            "/bin/bash", "/bin/sh", "/usr/bin/vim", "/usr/bin/nano",
            "/bin/chmod", "/bin/chown", "/usr/bin/passwd", "/bin/su"
        ]
        
        self.dangerous_commands = [
            "/bin/rm", "/usr/bin/dd", "/bin/mount", "/bin/umount",
            "/usr/bin/fdisk", "/sbin/mkfs", "/usr/bin/crontab"
        ]
        
        self.system_files = [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts",
            "/proc/version", "/sys/kernel/debug", "/dev/mem"
        ]

    def generate_ai_enhanced_data(self) -> Dict[str, List[str]]:
        """使用 FuzzWahahah AI 生成增强数据"""
        if not ENHANCED_MODE:
            return self._generate_fallback_data()
        
        try:
            print("🧠 使用 AI 增强生成 sudo 测试数据...")
            
            ai_data = {
                'commands': generate_protocol_data('sudo', 'commands', 100, use_ai=True),
            }
            print(f"✅ AI 生成了 {len(ai_data['commands'])} 个命令变异")
            
            return ai_data
            
        except Exception as e:
            print(f"⚠️  AI 增强失败，使用基础模式: {e}")
            return self._generate_fallback_data()

    def _generate_fallback_data(self) -> Dict[str, List[str]]:
        """基础数据生成（无AI增强）"""
        return {
            'options': self.base_sudo_options,
            'commands': self.base_commands + self.dangerous_commands,
            'users': ['root', 'admin', 'user', 'nobody', 'daemon'],
            'arguments': ['-rf /', '--help', '--version', '$(id)', '`whoami`'],
            'env_vars': ['PATH', 'HOME', 'USER', 'SHELL', 'TERM']
        }

    
    def save_seed(self, content: str, prefix: str = "sudo", seed_type: str = "basic") -> bool:
        """保存单个种子文件"""
        # 使用更有意义的文件名
        seed_file = self.output_dir / f"{prefix}_{seed_type}_{self.seed_count:06d}"
        
        try:
            # AFL++ 需要原始字节，不需要换行符
            with open(seed_file, 'wb') as f:
                f.write(content.encode('utf-8'))
            self.seed_count += 1
            return True
        except Exception as e:
            print(f"❌ 保存种子失败: {e}")
            return False

    def generate_all_seeds_no_save(self, seed_data, count: int = 1) -> List[str]:
        """生成所有类型的种子但不保存"""
        print(f"🌱 开始生成 {count} 个 AFL++ sudo 种子...")
        
        # 获取 AI 增强数据
        # ai_data = self.generate_ai_enhanced_data()
        load_protocol_ai_data('sudo')
        ai_data = grenerate_ai_enhanced_data("sudo", "commands", [seed_data], count)
        random.shuffle(ai_data)        

        save_ai_learning_data('sudo')
        return ai_data


    def generate_all_seeds(self, count: int = 2000) -> int:
        """生成所有类型的种子"""
        print(f"🌱 开始生成 {count} 个 AFL++ sudo 种子...")
        
        # 获取 AI 增强数据
        ai_data = self.generate_ai_enhanced_data()
        print(f"🧠 AI 数据生成完成: {ai_data}")
        # # 生成不同类型的种子
        all_seeds = ai_data.get('commands', [])
        
        # 随机选择指定数量的种子
        if len(all_seeds) > count:
            selected_seeds = random.sample(all_seeds, count)
        else:
            selected_seeds = all_seeds
            while len(selected_seeds) < count:
                selected_seeds.extend(random.sample(all_seeds, 
                    min(len(all_seeds), count - len(selected_seeds))))
        
        # 保存种子
        print("💾 保存种子文件...")
        
        saved_count = 0
        for seed_content in selected_seeds:
            if self.save_seed(seed_content, prefix="sudo", seed_type="command"):
                saved_count += 1
        
        print(f"✅ 成功生成并保存 {saved_count} 个种子到 {self.output_dir}")
        return saved_count
    
    def save_ai_seed(self, seed_content: str, prefix: str = "sudo", seed_type: str = "command") -> bool:
        print(learn_from_test_result(prefix, seed_type, seed_content, {'crashed': True}))
        save_ai_learning_data('sudo')
        return True

    def create_afl_script(self, target_binary: str = "sudo") -> str:
        """创建 AFL++ 启动脚本"""
        script_content = f"""#!/bin/bash
# AFL++ Sudo 模糊测试启动脚本
# 由 FuzzWahahah 自动生成

set -e

echo "🚀 启动 AFL++ sudo 模糊测试"
echo "种子目录: {self.output_dir}"
echo "目标程序: {target_binary}"

# 检查 AFL++ 是否安装
if ! command -v afl-fuzz &> /dev/null; then
    echo "❌ AFL++ 未安装，请先安装"
    exit 1
fi

# 设置 AFL++ 环境变量

export PYTHONPATH=/home/kami/fuzzwahh/fuzzwahahah-main
export AFL_PYTHON_MODULE=sudo_mutator
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_FAST_CAL=1
export AFL_AUTORESUME=1
export AFL_SKIP_BIN_CHECK=1
export AFL_HANG_TMOUT=1000

# 创建输出目录
mkdir -p afl_output

# 检查目标程序
if ! command -v {target_binary} &> /dev/null; then
    echo "❌ 目标程序 {target_binary} 不存在"
    exit 1
fi

# 启动 AFL++
echo "🎯 开始模糊测试..."
afl-fuzz -i {self.output_dir} -o afl_output -t 1000+ -m none -- {target_binary} @@

echo "✅ AFL++ 模糊测试完成"
echo "结果保存在: afl_output/"
echo "查看崩溃: ls afl_output/default/crashes/"
"""
        
        script_file = "run_afl_sudo.sh"
        with open(script_file, 'w') as f:
            f.write(script_content)
        
        os.chmod(script_file, 0o755)
        print(f"📜 已创建 AFL++ 启动脚本: {script_file}")
        return script_file

    def validate_seeds(self) -> bool:
        """验证生成的种子文件"""
        if not self.output_dir.exists():
            print("❌ 种子目录不存在")
            return False
        
        seed_files = list(self.output_dir.glob("*"))
        if not seed_files:
            print("❌ 没有找到种子文件")
            return False
        
        print(f"✅ 找到 {len(seed_files)} 个种子文件")
        
        # 检查文件大小分布
        sizes = [f.stat().st_size for f in seed_files]
        print(f"📊 种子大小: 最小={min(sizes)}字节, 最大={max(sizes)}字节, 平均={sum(sizes)//len(sizes)}字节")
        
        return True


def main():
    parser = argparse.ArgumentParser(
        description="AFL++ Sudo 种子生成器 - FuzzWahahah 集成版",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python3 afl_sudo_seed_generator.py --count 2000
  python3 afl_sudo_seed_generator.py --output my_seeds --count 5000 --create-script
  
生成种子后使用 AFL++:
  afl-fuzz -i afl_sudo_seeds -o afl_output -- sudo @@
        """
    )
    
    parser.add_argument("--output", "-o", default="seed_corpus/sudo",
                       help="种子输出目录 (默认: afl_sudo_seeds)")
    parser.add_argument("--count", "-c", type=int, default=10,
                       help="生成种子数量 (默认: 10)")
    parser.add_argument("--create-script", action="store_true",
                       help="创建 AFL++ 启动脚本")
    parser.add_argument("--target", "-t", default="sudo",
                       help="目标程序路径 (默认: sudo)")
    
    args = parser.parse_args()
    
    print("🔥 FuzzWahahah AFL++ Sudo 种子生成器")
    print("=" * 50)
    
    # 创建生成器
    generator = AFLSudoSeedGenerator(args.output)
    
    # 生成种子
    seed_count = generator.generate_all_seeds(args.count)
    
    # 创建启动脚本
    if args.create_script:
        script_file = generator.create_afl_script(args.target)
    
    print("\n🎯 生成完成！")
    print(f"种子目录: {args.output}")
    print(f"种子数量: {seed_count}")
    
    if args.create_script:
        print(f"启动脚本: {script_file}")
        print("\n运行方法:")
        print(f"  ./{script_file}")
    else:
        print("\n手动运行 AFL++:")
        print(f"  afl-fuzz -i {args.output} -o afl_output -- {args.target} @@")
    
    print("\n⚠️  警告: 这些种子包含潜在危险的命令，仅用于安全测试！")



seed_generator = AFLSudoSeedGenerator()



def test():
    print(generate_binary_data('format_string', 20))
    # load_protocol_ai_data('sudo')
    # _seed = grenerate_ai_enhanced_data("sudo", "commands", ["cat /etc/passwd"], 100)
    # random.shuffle(_seed)
    # # random.shuffle(_seed)
    # print(_seed[-1])
    # print(learn_from_test_result('sudo', 'commands', _seed[-1], {'crashed': True}))
    # save_ai_learning_data('sudo')

if __name__ == "__main__":
    main()
    #test()
