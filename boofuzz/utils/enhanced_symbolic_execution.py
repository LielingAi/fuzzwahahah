#!/usr/bin/env python3
"""
Enhanced Symbolic Execution Framework
增强的符号执行框架 - 统一、简化的符号执行接口
"""

import random
import string
import struct
import os
from typing import List, Dict, Any
from .symbolic_execution import SymbolicFuzzGenerator
# from ..sessions.session import Session
from boofuzz import *
from boofuzz import s_initialize, s_string, s_bytes, s_get


class ProtocolSymbolicEngine:
    """协议符号执行引擎 - 统一接口，集成AI学习功能"""

    def __init__(self):
        self.base_engine = SymbolicFuzzGenerator()

        # 协议模板目录管理
        self.protocol_templates_dir = "protocol_templates"
        self._ensure_protocol_templates_dir()
        self.protocol_templates = self._load_protocol_templates()

        # AI学习组件
        self.mutation_success_rates = {}  # 变异成功率
        self.crash_patterns = {}          # 崩溃模式
        self.max_cache_size = 10000       # 最大缓存大小，防止内存泄漏
        self.cache_cleanup_threshold = 0.8  # 缓存清理阈值

        # 统一的AI学习数据目录管理
        self.ai_data_dir = "ai_learning_data"
        self._ensure_ai_data_dir()
        self.learning_data_file = os.path.join(self.ai_data_dir, "global_learning_data.json")
        self.load_learning_data()
    
    def _load_protocol_templates(self) -> Dict[str, Dict]:
        """从JSON文件加载协议模板"""
        templates = {}

        try:
            import json
            import glob

            # 查找所有协议模板JSON文件
            template_files = glob.glob(os.path.join(self.protocol_templates_dir, "*.json"))

            for template_file in template_files:
                try:
                    with open(template_file, 'r', encoding='utf-8') as f:
                        template_data = json.load(f)

                    # 从文件名提取协议名称
                    protocol_name = os.path.splitext(os.path.basename(template_file))[0]
                    templates[protocol_name] = template_data

                except (json.JSONDecodeError, KeyError) as e:
                    print(f"⚠️  协议模板文件格式错误 {template_file}: {e}")
                except Exception as e:
                    print(f"❌ 加载协议模板文件失败 {template_file}: {e}")

            if templates:
                print(f"✅ 成功加载 {len(templates)} 个协议模板")
            else:
                print("⚠️  未找到协议模板文件，使用默认模板")
                templates = self._get_default_protocol_templates()

        except Exception as e:
            print(f"❌ 加载协议模板时发生错误: {e}")
            print("🔄 使用默认协议模板")
            templates = self._get_default_protocol_templates()

        return templates

    def _ensure_protocol_templates_dir(self):
        """确保协议模板目录存在，并创建默认模板文件"""
        try:
            if not os.path.exists(self.protocol_templates_dir):
                os.makedirs(self.protocol_templates_dir)
                print(f"📁 创建协议模板目录: {self.protocol_templates_dir}")

                # 创建默认协议模板文件
                self._create_default_template_files()

        except Exception as e:
            print(f"❌ 创建协议模板目录失败: {e}")

    def _create_default_template_files(self):
        """创建默认协议模板JSON文件"""
        try:
            import json
            default_templates = self._get_default_protocol_templates()

            for protocol_name, template_data in default_templates.items():
                template_file = os.path.join(self.protocol_templates_dir, f"{protocol_name}.json")

                # 只有文件不存在时才创建
                if not os.path.exists(template_file):
                    with open(template_file, 'w', encoding='utf-8') as f:
                        json.dump(template_data, f, indent=2, ensure_ascii=False)
                    print(f"📄 创建协议模板文件: {template_file}")

        except Exception as e:
            print(f"❌ 创建默认协议模板文件失败: {e}")

    def get_available_protocols(self) -> List[str]:
        """获取可用的协议列表"""
        return list(self.protocol_templates.keys())

    def protocol_exists(self, protocol: str) -> bool:
        """检查协议模板是否存在"""
        return protocol.lower() in self.protocol_templates

    def _get_default_protocol_templates(self) -> Dict[str, Dict]:
        """获取默认协议模板（向后兼容）"""
        return {}
    
    def generate_protocol_data(self, protocol: str, data_type: str, count: int = 10) -> List[Any]:
        """
        生成协议特定的测试数据

        Args:
            protocol: 协议名称 (http, ftp, redis, etc.)
            data_type: 数据类型 (methods, paths, commands, etc.)
            count: 生成数量

        Returns:
            生成的测试数据列表
        """
        # 输入验证
        if not isinstance(protocol, str) or not protocol.strip():
            raise ValueError("Protocol must be a non-empty string")

        if not isinstance(data_type, str) or not data_type.strip():
            raise ValueError("Data type must be a non-empty string")

        if not isinstance(count, int) or count <= 0:
            raise ValueError("Count must be a positive integer")

        protocol = protocol.lower().strip()
        data_type = data_type.strip()

        if protocol not in self.protocol_templates:
            raise ValueError(f"Unsupported protocol: {protocol}")

        template = self.protocol_templates[protocol]

        if data_type not in template:
            raise ValueError(f"Unsupported data type '{data_type}' for protocol '{protocol}'")
        
        base_data = template[data_type].copy()
        
        # 使用符号执行生成额外的变异
        try:
            enhanced_data = self._generate_symbolic_mutations(protocol, data_type, base_data, count)
            # enhanced_data 随机打乱顺序
            random.shuffle(enhanced_data)
            return enhanced_data[:count]
        except Exception as e:
            # 如果符号执行失败，返回基础数据
            print(f"Warning: Symbolic execution failed for {protocol}.{data_type}: {e}")
            return (base_data * ((count // len(base_data)) + 1))[:count]
    
    def _generate_symbolic_mutations(self, protocol: str, data_type: str, base_data: List, count: int) -> List[Any]:
        """使用符号执行生成变异数据"""
        enhanced_data = base_data.copy()
        
        # 根据数据类型生成不同的变异
        if data_type in ['usernames', 'passwords', 'emails', 'domains']:
            enhanced_data.extend(self._generate_string_mutations(base_data, count // 2))
        elif data_type in ['commands', 'methods', 'queries']:
            enhanced_data.extend(self._generate_command_mutations(base_data, count // 2))
        elif data_type in ['paths', 'keys', 'values']:
            enhanced_data.extend(self._generate_path_mutations(base_data, count // 2))
        elif data_type in ['qtypes', 'classes']:
            enhanced_data.extend(self._generate_numeric_mutations(base_data, count // 2))
        
        return enhanced_data
    
    def _generate_string_mutations(self, base_data: List[str], count: int) -> List[str]:
        """生成字符串变异（溢出用boofuzz原生字节）"""
        mutations = []
        
        for _ in range(count):
            if base_data:
                base = random.choice(base_data)
                mutation_type = random.choice(['overflow', 'injection', 'encoding', 'special_chars'])
                
                if mutation_type == 'overflow':
                    # 用boofuzz生成溢出字节，拼接到base后
                    overflow_bytes = self.generate_binary_data('overflow', random.randint(100, 1000))
                    # base转bytes再拼接，最后decode回str（忽略非法字符）
                    mutation = (base.encode('utf-8', errors='ignore') + overflow_bytes).decode('utf-8', errors='ignore')
                    mutations.append(mutation)
                elif mutation_type == 'injection':
                    injections = ["' OR 1=1 --", "<script>alert(1)</script>", "$(whoami)", "../../../etc/passwd"]
                    mutations.append(base + random.choice(injections))
                elif mutation_type == 'encoding':
                    mutations.append(base.replace('a', '%61').replace('e', '%65'))
                elif mutation_type == 'special_chars':
                    special = "!@#$%^&*()[]{}|\\:;\"'<>?,./"
                    mutations.append(base + ''.join(random.choices(special, k=random.randint(1, 10))))
        
        return mutations
    
    def _generate_command_mutations(self, base_data: List[str], count: int) -> List[str]:
        """生成命令变异"""
        mutations = []
        
        for _ in range(count):
            if base_data:
                base = random.choice(base_data)
                
                # 命令特定的变异
                mutation_type = random.choice(['case_change', 'extra_params', 'malformed'])
                
                if mutation_type == 'case_change':
                    mutations.append(base.lower() if base.isupper() else base.upper())
                elif mutation_type == 'extra_params':
                    mutations.append(base + ' ' + ''.join(random.choices(string.ascii_letters, k=10)))
                elif mutation_type == 'malformed':
                    mutations.append(base + '\x00\x01\x02')
        return mutations
    
    def _generate_path_mutations(self, base_data: List[str], count: int) -> List[str]:
        """生成路径变异"""
        mutations = []
        
        path_injections = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/proc/self/environ",
            "file:///etc/passwd",
            "\\\\server\\share\\file.txt"
        ]
        
        for _ in range(count):
            if random.choice([True, False]) and base_data:
                # 基于现有路径的变异
                base = random.choice(base_data)
                mutations.append(base + random.choice(path_injections))
            else:
                # 纯注入路径
                mutations.append(random.choice(path_injections))
        
        return mutations
    
    def _generate_numeric_mutations(self, base_data: List[int], count: int) -> List[Any]:
        """生成数值变异（溢出用boofuzz原生字节）"""
        mutations = []
        # special_values = [0, 1, -1, 255, 256, 65535, 65536, 0x7FFFFFFF, 0x80000000]

        for _ in range(count):
            mutation_type = random.choice(['int', 'overflow_bytes'])
            if mutation_type == 'int' and (random.choice([True, False]) and base_data):
                # 基于现有值的变异
                base = random.choice(base_data)
                mutations.append(base + random.randint(-100, 100))
            else:
                # 用boofuzz生成溢出字节
                overflow_bytes = self.generate_binary_data('overflow', random.randint(4, 16))
                mutations.append(overflow_bytes)
        return mutations
    
    def generate_binary_data(self, data_type: str, length: int = 1) -> bytes:
        """用 boofuzz 原生接口生成原始二进制数据"""
        if data_type == 'random':
            s_initialize("random")
            s_random(max_length=length)
            
            block = s_get("random")
            root_block = block.children[0]
            # 获取可能的变异数
            mutations = root_block.num_mutations()
            print(f"Total mutations: {mutations}")

            payloads = []
            for i in range(mutations):
                root_block.mutate(i)
                data = root_block.render()
                payloads.append(data)
                print(f"[{i}] {repr(data)}")

            # #req.render()
            # print(s_get("random"))
            return b""
        elif data_type == 'overflow':
            s_initialize("overflow")
            s_bytes(b"A" * length)
            req = Request("overflow")
            req.render()
            return req.render()
        elif data_type == 'null_bytes':
            s_initialize("null_bytes")
            s_bytes(b"\x00" * length)
            req = Request("null_bytes")
            req.render()
            return req.render()
        elif data_type == 'format_string':
            return b'%s%s%s%s%s%s%s%s%s%s%n%n%n%n%n%n%n%n%n%n'
        else:
            return b'test_data'
    
    def convert_to_bytes(self, data: Any, format_type: str = 'auto') -> bytes:
        """将数据转换为字节格式"""
        if isinstance(data, bytes):
            return data
        elif isinstance(data, str):
            return data.encode('utf-8', errors='ignore')
        elif isinstance(data, int):
            if format_type == 'big_endian_word':
                return struct.pack('>H', data & 0xFFFF)
            elif format_type == 'little_endian_word':
                return struct.pack('<H', data & 0xFFFF)
            elif format_type == 'big_endian_dword':
                return struct.pack('>L', data & 0xFFFFFFFF)
            elif format_type == 'little_endian_dword':
                return struct.pack('<L', data & 0xFFFFFFFF)
            else:
                return str(data).encode('utf-8')
        else:
            return str(data).encode('utf-8')

    def learn_from_feedback(self, protocol: str, data_type: str, mutation_data: str,
                          test_result: Dict[str, Any]):
        """AI学习：从测试结果中学习最有效的变异策略"""
        mutation_key = f"{protocol}_{data_type}"

        # 初始化成功率跟踪
        if mutation_key not in self.mutation_success_rates:
            self.mutation_success_rates[mutation_key] = {
                'total_tests': 0,
                'crashes': 0,
                'anomalies': 0,
                'patterns': {}
            }

        stats = self.mutation_success_rates[mutation_key]
        stats['total_tests'] += 1

        # 分析测试结果
        if test_result.get('crashed', False):
            stats['crashes'] += 1
            self._analyze_crash_pattern(mutation_data, test_result)
        elif test_result.get('response_time', 0) > 5.0:
            stats['anomalies'] += 1
        elif test_result.get('response_size', 0) != test_result.get('expected_size', 0):
            stats['anomalies'] += 1

        # 分析变异模式
        self._analyze_mutation_pattern(mutation_data, test_result, stats)

        # 定期保存学习数据和清理缓存
        if stats['total_tests'] % 100 == 0:
            self.save_learning_data()
            self._cleanup_cache_if_needed()

    def _analyze_crash_pattern(self, mutation_data: str, test_result: Dict[str, Any]):
        """分析崩溃模式"""
        # 缓存长度和小写版本以提高性能
        data_length = len(mutation_data)
        data_lower = mutation_data.lower()

        crash_features = {
            'length': data_length,
            'has_nullbytes': '\x00' in mutation_data,
            'has_format_strings': '%' in mutation_data,
            'has_sql_keywords': any(kw in data_lower for kw in ['union', 'select', 'drop']),
            'has_xss_tags': any(tag in data_lower for tag in ['<script', '<img']),
            'has_path_traversal': '../' in mutation_data,
            'special_char_ratio': sum(1 for c in mutation_data if not c.isalnum()) / max(data_length, 1)
        }

        crash_signature = test_result.get('crash_info', {}).get('signal', 'unknown')
        if crash_signature not in self.crash_patterns:
            self.crash_patterns[crash_signature] = []

        self.crash_patterns[crash_signature].append(crash_features)

    def _analyze_mutation_pattern(self, mutation_data: str, test_result: Dict[str, Any], stats: Dict):
        """分析变异模式的有效性"""
        # 缓存长度和小写版本以提高性能
        data_length = len(mutation_data)
        data_lower = mutation_data.lower()

        # 提取变异特征
        if data_length > 1000:
            pattern_type = 'overflow'
        elif any(kw in data_lower for kw in ['union', 'select', 'drop']):
            pattern_type = 'sql_injection'
        elif any(tag in data_lower for tag in ['<script', '<img']):
            pattern_type = 'xss'
        elif '../' in mutation_data:
            pattern_type = 'path_traversal'
        elif '%' in mutation_data:
            pattern_type = 'format_string'
        else:
            pattern_type = 'other'

        if pattern_type not in stats['patterns']:
            stats['patterns'][pattern_type] = {'tests': 0, 'successes': 0}

        stats['patterns'][pattern_type]['tests'] += 1
        if test_result.get('crashed', False) or test_result.get('response_time', 0) > 5.0:
            stats['patterns'][pattern_type]['successes'] += 1

    def get_ai_enhanced_mutations(self, protocol: str, data_type: str, base_data: List, count: int) -> List[Any]:
        """获取AI增强的变异数据"""
        mutation_key = f"{protocol}_{data_type}"
        enhanced_data = base_data.copy()
        # 如果有学习数据，应用AI增强
        if mutation_key in self.mutation_success_rates:
            stats = self.mutation_success_rates[mutation_key]

            # 根据成功模式生成更多变异
            for pattern_type, pattern_stats in stats['patterns'].items():
                if pattern_stats['tests'] > 10:  # 有足够的数据
                    success_rate = pattern_stats['successes'] / pattern_stats['tests']
                    if success_rate > 0.1:  # 成功率超过10%
                        # 生成更多这种类型的变异
                        enhanced_data.extend(self._generate_pattern_mutations(base_data, pattern_type, count // 4))
        else:
            print(f"ℹ️  无AI学习数据，使用基础变异数据: {mutation_key}")
        return enhanced_data[:count]

    def _generate_pattern_mutations(self, base_data: List, pattern_type: str, count: int) -> List[Any]:
        """遗传算法生成智能变异"""
        import random
        from boofuzz import s_initialize, s_string, s_get

        # 1. 初始种群 - 修复boofuzz集成问题
        population = []
        base_strs = [str(item) for item in base_data[:min(len(base_data), count)]]
        
        # 使用boofuzz生成基础变异数据
        try:
            s_initialize("pattern_mutation")
            s_string("test_data", max_len=1000, name="base")
            request = s_get("pattern_mutation")
            
            # 使用get_mutations()方法获取变异数据
            mutation_count = 0
            for mutation_list in request.get_mutations():
                if mutation_count >= min(20, count):
                    break
                try:
                    # mutation_list是Mutation对象列表
                    for mutation in mutation_list:
                        if hasattr(mutation, 'value'):
                            mutation_bytes = mutation.value
                        else:
                            mutation_bytes = mutation
                    
                    # 转换为字符串
                    if isinstance(mutation_bytes, bytes):
                        mutation_str = mutation_bytes.decode('utf-8', errors='ignore')
                    else:
                        mutation_str = str(mutation_bytes)
                    
                    population.append(mutation_str)
                    mutation_count += 1
                    if mutation_count >= min(20, count):
                        break
                except Exception as e:
                    print(f"⚠️ 处理变异数据失败: {e}")
                    continue
                
        except Exception as e:
            print(f"⚠️ boofuzz生成失败，使用基础数据: {e}")
            population = base_strs.copy()

        # 添加模式特定的模板
        pattern_templates = {
            'overflow': [
                lambda b: b + 'A' * 1000,
                lambda b: b + 'A' * 4096,
                lambda b: 'A' * 8192 + b
            ],
            'sql_injection': [
                lambda b: b + "' OR 1=1--",
                lambda b: b + "' UNION SELECT NULL--",
                lambda b: b + "'; DROP TABLE test--"
            ],
            'xss': [
                lambda b: b + "<script>alert('xss')</script>",
                lambda b: b + "<img src=x onerror=alert('xss')>",
                lambda b: b + "<svg onload=alert('xss')>"
            ],
            'path_traversal': [
                lambda b: b + "../../../etc/passwd",
                lambda b: b + "..\\..\\..\\windows\\system32\\config\\sam",
                lambda b: b + "....//....//....//etc/passwd"
            ],
            'format_string': [
                lambda b: b + "%s%s%s%s%s%s%s%s",
                lambda b: b + "%x%x%x%x%x%x%x%x",
                lambda b: b + "%n%n%n%n%n%n%n%n"
            ]
        }
        
        # 生成模式特定的初始种群
        for b in base_strs:
            if pattern_type in pattern_templates:
                for tpl in pattern_templates[pattern_type]:
                    try:
                        population.append(tpl(b))
                    except:
                        population.append(b)
            else:
                population.append(b)

        # 确保种群不为空
        if not population:
            population = ["test", "data", "mutation"]

        # 2. 遗传算法参数
        max_gen = 3
        pop_size = min(32, len(population))
        mutation_rate = 0.3

        # 3. 适应度函数
        def fitness(s):
            if not isinstance(s, str):
                s = str(s)
            score = len(s)
            score += sum(1 for c in s if not c.isalnum())
            return score

        # 4. 进化过程
        for _ in range(max_gen):
            # 选择
            try:
                selected = random.choices(population, k=min(pop_size, len(population)))
            except:
                selected = population[:pop_size]
                
            # 交叉
            children = []
            for _ in range(pop_size // 2):
                if len(selected) >= 2:
                    p1, p2 = random.sample(selected, 2)
                    p1_str, p2_str = str(p1), str(p2)
                    if len(p1_str) > 1 and len(p2_str) > 1:
                        cut = random.randint(1, min(len(p1_str), len(p2_str)) - 1)
                        child = p1_str[:cut] + p2_str[cut:]
                        children.append(child)
                        
            # 变异
            for i in range(len(children)):
                if random.random() < mutation_rate:
                    c = list(str(children[i]))
                    if c:
                        idx = random.randint(0, len(c) - 1)
                        c[idx] = random.choice("!@#$%^&*()_+-=;:'\"[]{}|,.<>/?0123456789")
                        children[i] = ''.join(c)
                        
            # 合并并选优
            population.extend(children)
            try:
                population = sorted(set(str(p) for p in population), key=fitness, reverse=True)[:pop_size]
            except:
                population = list(set(str(p) for p in population))[:pop_size]

        # 5. 返回多样化结果
        result_count = min(count, len(population))
        return random.sample(population, result_count) if population else ["default_mutation"]

    def save_learning_data(self):
        """保存AI学习数据"""
        try:
            import json
            learning_data = {
                'mutation_success_rates': self.mutation_success_rates,
                'crash_patterns': self.crash_patterns
            }
            with open(self.learning_data_file, 'w', encoding='utf-8') as f:
                json.dump(learning_data, f, indent=2, ensure_ascii=False)
            print(f"💾 AI学习数据已保存: {self.learning_data_file}")
        except (PermissionError, OSError) as e:
            print(f"❌ 无法保存学习数据文件: {e}")
        except (TypeError, ValueError) as e:
            print(f"❌ 学习数据序列化失败: {e}")
        except Exception as e:
            print(f"❌ 保存学习数据时发生未知错误: {e}")

    def load_learning_data(self):
        """加载AI学习数据"""
        try:
            import json
            if os.path.exists(self.learning_data_file):
                with open(self.learning_data_file, 'r', encoding='utf-8') as f:
                    learning_data = json.load(f)
                self.mutation_success_rates = learning_data.get('mutation_success_rates', {})
                self.crash_patterns = learning_data.get('crash_patterns', {})
                print(f"✅ 成功加载AI学习数据: {self.learning_data_file}")
        except (FileNotFoundError, PermissionError) as e:
            print(f"⚠️  无法访问学习数据文件: {e}")
            self.mutation_success_rates = {}
            self.crash_patterns = {}
        except (json.JSONDecodeError, KeyError) as e:
            print(f"⚠️  学习数据文件格式错误: {e}")
            self.mutation_success_rates = {}
            self.crash_patterns = {}
        except Exception as e:
            print(f"❌ 加载学习数据时发生未知错误: {e}")
            self.mutation_success_rates = {}
            self.crash_patterns = {}

    def _cleanup_cache_if_needed(self):
        """清理缓存以防止内存泄漏"""
        total_cache_items = (len(self.mutation_success_rates) +
                           sum(len(patterns) for patterns in self.crash_patterns.values()))

        if total_cache_items > self.max_cache_size * self.cache_cleanup_threshold:
            print(f"🧹 清理AI学习缓存 (当前项目: {total_cache_items})")

            # 清理最旧的变异成功率数据
            if len(self.mutation_success_rates) > self.max_cache_size // 2:
                # 保留测试次数最多的一半数据
                sorted_mutations = sorted(
                    self.mutation_success_rates.items(),
                    key=lambda x: x[1]['total_tests'],
                    reverse=True
                )
                keep_count = len(sorted_mutations) // 2
                self.mutation_success_rates = dict(sorted_mutations[:keep_count])

            # 清理崩溃模式数据
            for crash_sig in list(self.crash_patterns.keys()):
                if len(self.crash_patterns[crash_sig]) > 100:
                    # 只保留最近的100个崩溃记录
                    self.crash_patterns[crash_sig] = self.crash_patterns[crash_sig][-100:]

            print(f"✅ 缓存清理完成")

    def clear_all_cache(self):
        """清空所有缓存"""
        self.mutation_success_rates.clear()
        self.crash_patterns.clear()
        print("🗑️  所有AI学习缓存已清空")

    def _ensure_ai_data_dir(self):
        """确保AI学习数据目录存在"""
        try:
            if not os.path.exists(self.ai_data_dir):
                os.makedirs(self.ai_data_dir)
                print(f"📁 创建AI学习数据目录: {self.ai_data_dir}")
        except Exception as e:
            print(f"❌ 创建AI学习数据目录失败: {e}")

    def save_protocol_learning_data(self, protocol: str):
        """保存特定协议的学习数据"""
        try:
            import json
            protocol_file = os.path.join(self.ai_data_dir, f"{protocol}_learning_data.json")

            # 过滤出该协议相关的数据
            protocol_data = {}
            for key, value in self.mutation_success_rates.items():
                if key.startswith(f"{protocol}_"):
                    protocol_data[key] = value

            protocol_crashes = {}
            for key, value in self.crash_patterns.items():
                # 简单的协议关联判断
                protocol_crashes[key] = value

            learning_data = {
                'protocol': protocol,
                'mutation_success_rates': protocol_data,
                'crash_patterns': protocol_crashes,
                'timestamp': __import__('time').time()
            }

            with open(protocol_file, 'w', encoding='utf-8') as f:
                json.dump(learning_data, f, indent=2, ensure_ascii=False)

            print(f"💾 {protocol.upper()}协议学习数据已保存: {protocol_file}")
            return True

        except Exception as e:
            print(f"❌ 保存{protocol}协议学习数据失败: {e}")
            return False

    def load_protocol_learning_data(self, protocol: str):
        """加载特定协议的学习数据"""
        try:
            import json
            protocol_file = os.path.join(self.ai_data_dir, f"{protocol}_learning_data.json")

            if os.path.exists(protocol_file):
                with open(protocol_file, 'r', encoding='utf-8') as f:
                    learning_data = json.load(f)

                # 合并协议特定的学习数据
                protocol_success_rates = learning_data.get('mutation_success_rates', {})
                protocol_crashes = learning_data.get('crash_patterns', {})

                self.mutation_success_rates.update(protocol_success_rates)
                self.crash_patterns.update(protocol_crashes)

                print(f"✅ 加载{protocol.upper()}协议学习数据: {protocol_file}")
                return True
            else:
                print(f"ℹ️  {protocol.upper()}协议学习数据文件不存在，将创建新的")
                return False

        except Exception as e:
            print(f"❌ 加载{protocol}协议学习数据失败: {e}")
            return False

# 全局实例
protocol_symbolic_engine = ProtocolSymbolicEngine()

# 便捷函数
def generate_protocol_data(protocol: str, data_type: str, count: int = 10, use_ai: bool = True) -> List[Any]:
    """便捷函数：生成协议数据，支持AI增强"""
    if use_ai:
        # 先获取基础数据（不使用AI增强，避免递归）
        base_data = protocol_symbolic_engine.generate_protocol_data(protocol, data_type, count // 2)
        # 然后应用AI增强
        return protocol_symbolic_engine.get_ai_enhanced_mutations(protocol, data_type, base_data, count)
    else:
        return protocol_symbolic_engine.generate_protocol_data(protocol, data_type, count)


def grenerate_ai_enhanced_data(protocol: str, data_type: str, base_data: List, count: int) -> List[Any]:
    """便捷函数：获取AI增强的变异数据"""
    return protocol_symbolic_engine.get_ai_enhanced_mutations(protocol, data_type, base_data, count)

def generate_binary_data(data_type: str, length: int = 1) -> bytes:
    """便捷函数：生成二进制数据"""
    return protocol_symbolic_engine.generate_binary_data(data_type, length)

def convert_to_bytes(data: Any, format_type: str = 'auto') -> bytes:
    """便捷函数：转换为字节"""
    return protocol_symbolic_engine.convert_to_bytes(data, format_type)

def learn_from_test_result(protocol: str, data_type: str, mutation_data: str, test_result: Dict[str, Any]):
    """便捷函数：AI学习反馈"""
    protocol_symbolic_engine.learn_from_feedback(protocol, data_type, mutation_data, test_result)

def save_ai_learning_data(protocol: str = ""):
    """便捷函数：保存AI学习数据"""
    if protocol:
        protocol_symbolic_engine.save_protocol_learning_data(protocol)
    protocol_symbolic_engine.save_learning_data()

def load_protocol_ai_data(protocol: str):
    """便捷函数：加载协议特定的AI学习数据"""
    return protocol_symbolic_engine.load_protocol_learning_data(protocol)
