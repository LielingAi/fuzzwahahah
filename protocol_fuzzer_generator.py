#!/usr/bin/env python3
"""
Protocol Fuzzer Generator
智能协议模糊测试生成器 - 通过配置自动生成boofuzz_*_fuzzer.py文件
"""

import os
import json
import yaml
from typing import Dict, List, Any, Optional
from jinja2 import Template

class ProtocolFuzzerGenerator:
    """协议模糊测试生成器"""

    def __init__(self):
        self.template_dir = "templates"
        self.output_dir = "."
        self.ensure_template_dir()

        # 初始化协议符号执行引擎以获取协议模板信息
        try:
            from boofuzz.utils.enhanced_symbolic_execution import ProtocolSymbolicEngine
            self.symbolic_engine = ProtocolSymbolicEngine()
        except ImportError:
            print("⚠️  无法导入符号执行引擎，将使用基础功能")
            self.symbolic_engine = None
    
    def ensure_template_dir(self):
        """确保模板目录存在"""
        if not os.path.exists(self.template_dir):
            os.makedirs(self.template_dir)

    def get_available_protocols(self) -> List[str]:
        """获取可用的协议模板列表"""
        if self.symbolic_engine:
            return self.symbolic_engine.get_available_protocols()
        else:
            # 如果符号执行引擎不可用，返回基础协议列表
            return []

    def protocol_exists(self, protocol: str) -> bool:
        """检查协议模板是否存在"""
        if self.symbolic_engine:
            return self.symbolic_engine.protocol_exists(protocol)
        else:
            # 基础检查
            return protocol.lower() in []
    
    def load_protocol_config(self, config_file: str) -> Dict[str, Any]:
        """加载协议配置文件"""
        with open(config_file, 'r', encoding='utf-8') as f:
            if config_file.endswith('.json'):
                return json.load(f)
            elif config_file.endswith(('.yml', '.yaml')):
                return yaml.safe_load(f)
            else:
                raise ValueError("Unsupported config file format. Use JSON or YAML.")
    
    def generate_fuzzer(self, config_file: str,  symbolic_file: str, output_file: str = None) -> str:
        """根据配置生成模糊测试工具"""
        config = self.load_protocol_config(config_file)
        symbolic_data_config = self.load_protocol_config(symbolic_file)
        # 验证配置
        self._validate_config(config)
        
        # 生成代码
        fuzzer_code = self._generate_fuzzer_code(config, symbolic_data_config)
        
        # 确定输出文件名
        if not output_file:
            protocol_name = config['protocol']['name'].lower()
            output_file = f"boofuzz_{protocol_name}_fuzzer.py"
        
        # 写入文件
        output_path = os.path.join(self.output_dir, output_file)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(fuzzer_code)
        
        print(f"✅ 生成协议模糊测试工具: {output_path}")
        return output_path
    
    def _validate_config(self, config: Dict[str, Any]):
        """验证配置文件"""
        required_fields = ['protocol', 'requests']
        for field in required_fields:
            if field not in config:
                raise ValueError(f"Missing required field: {field}")
        
        protocol_fields = ['name', 'port', 'transport']
        for field in protocol_fields:
            if field not in config['protocol']:
                raise ValueError(f"Missing protocol field: {field}")
    
    def _generate_fuzzer_code(self, config: Dict[str, Any], symbolic_data_config: Dict[str, Any]) -> str:
        """生成模糊测试代码"""
        template = self._get_fuzzer_template()
        
        # 准备模板变量
        template_vars = {
            'protocol': config['protocol'],
            'requests': config['requests'],
            'imports': config.get('imports', []),
            'helpers': config.get('helpers', {}),
            'symbolic_data': symbolic_data_config,
            'web_port': config.get('web_port', 26000),
            'description': config.get('description', f"{config['protocol']['name']} Protocol Fuzzer")
        }

        # 确保所有字段都是可序列化的，并预处理values字段
        import json
        for req in template_vars['requests']:
            for field in req.get('fields', []):
                if 'values' in field:
                    try:
                        # 尝试将values转换为字符串表示
                        if hasattr(field['values'], '__call__'):
                            # 如果是函数，使用空列表
                            field['values_str'] = "[]"
                        else:
                            # 正常的值，转换为JSON字符串
                            field['values_str'] = json.dumps(field['values'])
                    except Exception as e:
                        print(f"⚠️  处理字段 {field.get('name', 'Unknown')} 的values时出错: {e}")
                        field['values_str'] = "[]"
        
        # 渲染模板
        try:
            return template.render(**template_vars)
        except Exception as e:
            print(f"❌ 模板渲染失败: {e}")
            print(f"📋 模板变量: {list(template_vars.keys())}")
            # 检查requests中的字段
            for i, req in enumerate(template_vars.get('requests', [])):
                print(f"Request {i}: {req.get('name', 'Unknown')}")
                for j, field in enumerate(req.get('fields', [])):
                    if 'values' in field:
                        print(f"  Field {j} values type: {type(field['values'])}")
                        print(f"  Field {j} values: {field['values']}")
            raise
    
    def _get_fuzzer_template(self) -> Template:
        """获取模糊测试模板"""
        template_content = '''#!/usr/bin/env python3
"""
{{ description }}
基于boofuzz的{{ protocol.name }}协议模糊测试工具，集成符号执行和智能优化
"""

import sys
import time
import argparse
{% for import_item in imports -%}
import {{ import_item }}
{% endfor -%}
from boofuzz import *
from boofuzz.utils.enhanced_symbolic_execution import (
    generate_protocol_data,
    convert_to_bytes,
    learn_from_test_result,
    save_ai_learning_data
)

def create_{{ protocol.name.lower() }}_requests():
    """创建增强的{{ protocol.name }}请求模板"""
    
    print("🧠 生成{{ protocol.name }}符号执行数据...")
    
    # 使用增强的符号执行框架生成测试数据
    {% for data_name in symbolic_data -%}
    symbolic_{{ data_name }} = generate_protocol_data('{{ protocol.name.lower() }}', '{{ data_name }}', {{ symbolic_data[data_name].len | default(10) }}, use_ai=True)
    {% endfor %}
    
    print(f"✅ 准备了符号执行测试数据")
    
    requests = []
    
    {% for request in requests -%}
    # {{ loop.index }}. {{ request.name }}
    s_initialize("{{ request.id }}")
    
    {% for field in request.fields -%}
    {% if field.type == 'static' -%}
    s_{{ field.primitive }}({{ field.value }}, name="{{ field.name }}"{% if field.endian %}, endian="{{ field.endian }}"{% endif %})
    {% elif field.type == 'size' -%}
    s_size("{{ field.target }}", length={{ field.length }}{% if field.endian %}, endian="{{ field.endian }}"{% endif %}{% if field.name %}, name="{{ field.name }}"{% endif %})
    {% elif field.type == 'block_start' -%}
    s_block_start("{{ field.name }}")
    {% elif field.type == 'block_end' -%}
    s_block_end("{{ field.name }}")
    {% elif field.type == 'group' -%}
    {% if field.data_source -%}
    # 使用符号执行数据
    {% if field.convert_to_bytes -%}
    {{ field.name }}_bytes = [convert_to_bytes(item, '{{ field.byte_format | default("auto") }}') for item in {{ field.data_source }}]
    s_group("{{ field.name }}", values={{ field.name }}_bytes)
    {% else -%}
    s_group("{{ field.name }}", values={{ field.data_source }})
    {% endif -%}
    {% else -%}
    # 静态数据组
    {{ field.name }}_data = {{ field.values_str }}
    s_group("{{ field.name }}", values={{ field.name }}_data)
    {% endif -%}
    {% elif field.type == 'string' -%}
    s_string("{{ field.value }}")
    {% elif field.type == 'delim' -%}
    s_delim("{{ field.value }}")
    {% elif field.type == 'random' -%}
    s_random("{{ field.name }}", min_length={{ field.min_length }}, max_length={{ field.max_length }})
    {% elif field.type == 'custom' -%}
    # 自定义字段: {{ field.description }}
    {{ field.code }}
    {% endif -%}
    {% endfor %}
    
    requests.append(s_get("{{ request.id }}"))
    
    {% endfor -%}
    
    return requests

{% for helper_name, helper_code in helpers.items() -%}
def {{ helper_name }}():
    """{{ helper_code.description | default('Helper function') }}"""
    {{ helper_code.code }}

{% endfor -%}

def main():
    parser = argparse.ArgumentParser(description="Enhanced {{ protocol.name }} Protocol Fuzzer")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("port", type=int, help="Target port (default: {{ protocol.port }})", nargs='?', default={{ protocol.port }})
    parser.add_argument("--timeout", type=int, default=5, help="Connection timeout")
    parser.add_argument("--dry-run", action="store_true", help="Test without actual fuzzing")
    parser.add_argument("--web-port", type=int, default={{ web_port }}, help="Web interface port")
    {% if protocol.transport == 'ssl' -%}
    parser.add_argument("--ssl", action="store_true", help="Use SSL/TLS")
    {% endif -%}
    {% if protocol.auth_required -%}
    parser.add_argument("--username", default="{{ protocol.default_username | default('admin') }}", help="{{ protocol.name }} username")
    parser.add_argument("--password", default="{{ protocol.default_password | default('password') }}", help="{{ protocol.name }} password")
    {% endif -%}
    
    args = parser.parse_args()
    
    print("🚀 Enhanced {{ protocol.name }} Protocol Fuzzer")
    print("=" * 50)
    print(f"Target: {args.target}:{args.port}")
    {% if protocol.transport == 'ssl' -%}
    print(f"SSL: {'Yes' if args.ssl else 'No'}")
    {% endif -%}
    {% if protocol.auth_required -%}
    print(f"Username: {args.username}")
    {% endif -%}
    print(f"Web Interface: http://localhost:{args.web_port}")
    print()
    
    if args.dry_run:
        print("🧪 Dry run mode - testing request generation...")
        requests = create_{{ protocol.name.lower() }}_requests()
        print(f"✅ Successfully created {len(requests)} {{ protocol.name }} request templates")
        
        for i, req in enumerate(requests):
            print(f"\\n📋 Request {i+1}: {req.name}")
            try:
                rendered = req.render()
                print(f"   Size: {len(rendered)} bytes")
                {%- if protocol.is_text_protocol %}
                # {{ protocol.name }}是文本协议，可以直接显示
                preview = rendered.decode('utf-8', errors='ignore')[:100]
                print(f"   Preview: {preview}...")
                {%- else %}
                # {{ protocol.name }}协议是二进制的，显示十六进制
                hex_preview = rendered[:50].hex()
                print(f"   Hex Preview: {hex_preview}...")
                {%- endif %}
            except Exception as e:
                print(f"   Error: {e}")

        print("\\n✅ Dry run completed successfully!")
        return
    
    # 创建会话
    session = Session(
        target=Target(
            connection=SocketConnection(
                host=args.target,
                port=args.port,
                proto="{% if protocol.transport == 'ssl' %}ssl{% elif protocol.transport == 'udp' %}udp{% else %}tcp{% endif %}",
                timeout=args.timeout
            )
        ),
        web_port=args.web_port,
        check_data_received_each_request=False
    )

    # 启用AI自适应策略
    session.ai_strategy_enabled = True
    session.ai_decision_threshold = 0.15
    session.ai_adaptation_interval = 50

    print("🤖 AI自适应策略已启用")
    
    # 创建{{ protocol.name }}请求
    requests = create_{{ protocol.name.lower() }}_requests()
    
    # 添加请求到会话
    for request in requests:
        session.connect(s_get("target"), request)
    
    print(f"🚀 开始{{ protocol.name }}协议模糊测试...")
    print(f"📊 监控界面: http://localhost:{args.web_port}")
    {% if protocol.dangerous -%}
    print("⚠️  警告: 这将对目标{{ protocol.name }}服务器执行潜在危险的操作!")
    {% endif -%}
    
    try:
        session.fuzz()
    except KeyboardInterrupt:
        print("\\n⏹️  用户中断测试")
    except Exception as e:
        print(f"\\n❌ 测试过程中出现错误: {e}")
    finally:
        print("🏁 {{ protocol.name }}模糊测试完成")

if __name__ == "__main__":
    main()
'''
        return Template(template_content)
    
    def create_sample_config(self, protocol_name: str, output_file: str = None):
        """创建示例配置文件"""
        # 检查协议是否存在
        if not self.protocol_exists(protocol_name):
            print(f"❌ 协议 '{protocol_name}' 不存在")
            print("📋 可用协议:")
            for protocol in sorted(self.get_available_protocols()):
                print(f"   - {protocol}")
            return None

        if not output_file:
            output_file = f"{protocol_name.lower()}_config.yaml"

        sample_config = self._get_sample_config(protocol_name)

        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.dump(sample_config, f, default_flow_style=False, allow_unicode=True)

        print(f"✅ 创建示例配置文件: {output_file}")
        return output_file
    
    def _get_sample_config(self, protocol_name: str) -> Dict[str, Any]:
        """获取示例配置"""
        if protocol_name.lower() == 'telnet':
            return {
                'protocol': {
                    'name': 'Telnet',
                    'port': 23,
                    'transport': 'tcp',
                    'is_text_protocol': True,
                    'auth_required': True,
                    'default_username': 'admin',
                    'default_password': 'password',
                    'dangerous': True
                },
                'description': 'Telnet Protocol Fuzzer with Authentication Testing',
                'web_port': 26010,
                'imports': ['struct'],
                'symbolic_data': {
                    'symbolic_usernames': {'type': 'usernames', 'count': 8},
                    'symbolic_passwords': {'type': 'passwords', 'count': 8},
                    'symbolic_commands': {'type': 'commands', 'count': 10}
                },
                'requests': [
                    {
                        'name': 'Telnet Login Sequence',
                        'id': 'TELNET_LOGIN',
                        'fields': [
                            {'type': 'group', 'name': 'username', 'data_source': 'symbolic_usernames'},
                            {'type': 'delim', 'value': '\\r\\n'},
                            {'type': 'group', 'name': 'password', 'data_source': 'symbolic_passwords'},
                            {'type': 'delim', 'value': '\\r\\n'}
                        ]
                    },
                    {
                        'name': 'Telnet Command Execution',
                        'id': 'TELNET_COMMAND',
                        'fields': [
                            {'type': 'group', 'name': 'command', 'data_source': 'symbolic_commands'},
                            {'type': 'delim', 'value': '\\r\\n'}
                        ]
                    }
                ]
            }
        else:
            # 通用示例
            return {
                'protocol': {
                    'name': protocol_name.title(),
                    'port': 8080,
                    'transport': 'tcp',
                    'is_text_protocol': True,
                    'dangerous': False
                },
                'description': f'{protocol_name.title()} Protocol Fuzzer',
                'web_port': 26000,
                'symbolic_data': {
                    'test_data': {'type': 'values', 'count': 10}
                },
                'requests': [
                    {
                        'name': f'{protocol_name.title()} Basic Request',
                        'id': f'{protocol_name.upper()}_BASIC',
                        'fields': [
                            {'type': 'string', 'value': 'HELLO'},
                            {'type': 'delim', 'value': '\\r\\n'}
                        ]
                    }
                ]
            }

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Protocol Fuzzer Generator")
    parser.add_argument("--config", help="Protocol configuration file")
    parser.add_argument("--symbolic", help="Protocol to generate symbolic data for .json")
    parser.add_argument("--output", help="Output fuzzer file")
    parser.add_argument("--create-sample", help="Create sample config for protocol")
    parser.add_argument("--list-templates", action="store_true", help="List available templates")

    args = parser.parse_args()
    
    generator = ProtocolFuzzerGenerator()
    
    if args.create_sample:
        generator.create_sample_config(args.create_sample)
    elif args.config and args.symbolic:        
        generator.generate_fuzzer(args.config, args.symbolic ,args.output)
    elif args.list_templates:
        print("📋 Available protocol templates:")
        available_protocols = generator.get_available_protocols()
        for protocol in sorted(available_protocols):
            print(f"- {protocol}")
        print(f"\\n💡 Total: {len(available_protocols)} protocols available")
        print("💡 Use --create-sample <protocol> to create a configuration template")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
