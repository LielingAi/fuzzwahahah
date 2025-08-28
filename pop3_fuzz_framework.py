#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
一体化POP3高级fuzz测试框架
集成测试执行、高级分析和报告生成
"""

import re
import sys
import subprocess
import argparse
import time
import json
from collections import defaultdict
from datetime import datetime
import os

class POP3FuzzFramework:
    def __init__(self, client_path="./pop3_fuzz_client_v2.exe", iterations=10):
        self.client_path = client_path
        self.iterations = iterations
        self.results = []
        self.vulnerabilities = []
        
    def run_single_test(self, iteration):
        """执行单次测试"""
        try:
            # 执行客户端程序
            result = subprocess.run(
                [self.client_path], 
                capture_output=True, 
                text=True, 
                timeout=30  # 30秒超时
            )
            
            return {
                'iteration': iteration,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'success': True,
                'timestamp': datetime.now().isoformat()
            }
        except subprocess.TimeoutExpired:
            return {
                'iteration': iteration,
                'returncode': -1,
                'stdout': '',
                'stderr': 'Timeout',
                'success': False,
                'timeout': True,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'iteration': iteration,
                'returncode': -2,
                'stdout': '',
                'stderr': str(e),
                'success': False,
                'exception': True,
                'timestamp': datetime.now().isoformat()
            }
    
    def detect_chain_reaction_potential(self, output):
        """检测链式反应利用潜力"""
        indicators = []
        
        # 检测多个EOB触发点
        eob_matches = re.findall(r'POTENTIAL.*EOB trigger pattern', output)
        if len(eob_matches) > 1:
            indicators.append({
                'type': 'multiple_eob_triggers',
                'count': len(eob_matches),
                'description': f'发现{len(eob_matches)}个EOB触发点'
            })
        
        # 检测多个点号去转义失败
        dot_matches = re.findall(r"Line starts with '\.\.'", output)
        if len(dot_matches) > 2:
            indicators.append({
                'type': 'multiple_dot_failures',
                'count': len(dot_matches),
                'description': f'发现{len(dot_matches)}处点号去转义失败'
            })
        
        # 检测异常字节序列组合
        byte_matches = re.findall(r'Unexpected byte sequence', output)
        if len(byte_matches) > 2:
            indicators.append({
                'type': 'multiple_byte_anomalies',
                'count': len(byte_matches),
                'description': f'发现{len(byte_matches)}个异常字节序列'
            })
        
        return indicators
    
    def detect_data_stream_manipulation(self, output):
        """检测数据流操纵可能性"""
        indicators = []
        
        # 检测复杂EOB触发模式
        complex_eob = re.findall(r'EOB trigger pattern.*\..*\.', output)
        if complex_eob:
            indicators.append({
                'type': 'complex_eob_pattern',
                'count': len(complex_eob),
                'description': '发现复杂的EOB触发模式'
            })
        
        # 检测头部边界操纵
        header_manipulation = re.findall(r'(Found standard header terminator.*Unexpected byte sequence)', output, re.DOTALL)
        if header_manipulation:
            indicators.append({
                'type': 'header_boundary_manipulation',
                'description': '头部边界附近发现异常序列'
            })
        
        return indicators
    
    def detect_critical_issues(self, test_result):
        """检测严重安全问题"""
        issues = []
        
        # 程序异常退出
        if not test_result['success']:
            if test_result.get('timeout'):
                issues.append({
                    'type': 'timeout',
                    'severity': 'CRITICAL',
                    'description': '程序执行超时'
                })
            elif test_result.get('exception'):
                issues.append({
                    'type': 'exception',
                    'severity': 'CRITICAL',
                    'description': f'程序异常退出: {test_result["stderr"]}'
                })
            else:
                issues.append({
                    'type': 'abnormal_exit',
                    'severity': 'HIGH',
                    'description': f'程序非正常退出，返回码: {test_result["returncode"]}'
                })
        
        # 检测链式反应潜力
        chain_indicators = self.detect_chain_reaction_potential(test_result['stdout'])
        if chain_indicators:
            issues.append({
                'type': 'chain_reaction_potential',
                'severity': 'HIGH',
                'description': '链式反应利用潜力',
                'details': chain_indicators
            })
        
        # 检测数据流操纵
        manipulation_indicators = self.detect_data_stream_manipulation(test_result['stdout'])
        if manipulation_indicators:
            issues.append({
                'type': 'data_stream_manipulation',
                'severity': 'HIGH',
                'description': '数据流操纵可能性',
                'details': manipulation_indicators
            })
        
        return issues
    
    def run_fuzz_tests(self):
        """执行fuzz测试"""
        print(f"=== 启动POP3高级fuzz测试 ===")
        print(f"客户端: {self.client_path}")
        print(f"迭代次数: {self.iterations}")
        print(f"开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 50)
        
        critical_issues = 0
        high_risk_issues = 0
        
        for i in range(self.iterations):
            print(f"执行测试 [{i+1}/{self.iterations}]...", end='', flush=True)
            
            # 执行单次测试
            result = self.run_single_test(i+1)
            self.results.append(result)
            
            # 检测安全问题
            issues = self.detect_critical_issues(result)
            
            # 统计严重问题
            for issue in issues:
                if issue['severity'] == 'CRITICAL':
                    critical_issues += 1
                elif issue['severity'] == 'HIGH':
                    high_risk_issues += 1
            
            # 记录发现的问题
            if issues:
                self.vulnerabilities.extend(issues)
                print(f" 发现{len(issues)}个问题")
            else:
                print(" 无问题")
            
            # 如果发现严重问题，立即报告
            if critical_issues > 0:
                print(f"[紧急] 发现{critical_issues}个严重安全问题！")
                break
        
        print("-" * 50)
        print(f"测试完成: {self.iterations}次迭代")
        print(f"严重问题: {critical_issues}个")
        print(f"高风险问题: {high_risk_issues}个")
        
        return critical_issues, high_risk_issues
    
    def generate_detailed_report(self):
        """生成详细报告"""
        report = []
        report.append("=" * 60)
        report.append("    POP3协议高级安全测试详细报告")
        report.append("=" * 60)
        report.append(f"测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"客户端: {self.client_path}")
        report.append(f"迭代次数: {self.iterations}")
        report.append("")
        
        # 统计信息
        successful_tests = sum(1 for r in self.results if r['success'])
        failed_tests = len(self.results) - successful_tests
        timeouts = sum(1 for r in self.results if r.get('timeout'))
        exceptions = sum(1 for r in self.results if r.get('exception'))
        
        report.append("=== 测试统计 ===")
        report.append(f"总测试数: {len(self.results)}")
        report.append(f"成功测试: {successful_tests}")
        report.append(f"失败测试: {failed_tests}")
        report.append(f"超时测试: {timeouts}")
        report.append(f"异常测试: {exceptions}")
        report.append("")
        
        # 问题分类统计
        critical_issues = [v for v in self.vulnerabilities if v['severity'] == 'CRITICAL']
        high_risk_issues = [v for v in self.vulnerabilities if v['severity'] == 'HIGH']
        
        report.append("=== 安全问题统计 ===")
        report.append(f"严重问题: {len(critical_issues)}")
        report.append(f"高风险问题: {len(high_risk_issues)}")
        report.append("")
        
        # 详细问题列表
        if self.vulnerabilities:
            report.append("=== 详细安全问题 ===")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                report.append(f"{i}. [{vuln['severity']}] {vuln['type']}")
                report.append(f"   描述: {vuln['description']}")
                
                if 'details' in vuln:
                    report.append("   详细信息:")
                    for detail in vuln['details']:
                        report.append(f"     - {detail['description']}")
                        if 'count' in detail:
                            report.append(f"       数量: {detail['count']}")
                report.append("")
        
        # 严重问题详情
        if critical_issues:
            report.append("=== 严重安全问题详情 ===")
            for i, issue in enumerate(critical_issues, 1):
                report.append(f"{i}. {issue['type']}: {issue['description']}")
            report.append("")
            report.append("[紧急] 发现严重安全问题，建议立即停止服务并修复！")
        
        # 高风险问题详情
        if high_risk_issues:
            report.append("=== 高风险问题详情 ===")
            for i, issue in enumerate(high_risk_issues, 1):
                report.append(f"{i}. {issue['type']}: {issue['description']}")
                if 'details' in issue:
                    for detail in issue['details']:
                        report.append(f"   - {detail['description']}")
            report.append("")
            report.append("[警告] 发现高风险问题，建议尽快评估和修复。")
        
        # 建议措施
        report.append("=== 建议措施 ===")
        if critical_issues:
            report.append("1. 立即停止受影响的服务")
            report.append("2. 修复程序异常退出问题")
            report.append("3. 实施严格的输入验证和错误处理")
            report.append("4. 增加超时和资源限制机制")
        elif high_risk_issues:
            report.append("1. 评估链式反应利用风险")
            report.append("2. 审查数据完整性保护机制")
            report.append("3. 实施更严格的协议合规性检查")
            report.append("4. 定期执行安全测试")
        else:
            report.append("1. 继续监控系统运行状态")
            report.append("2. 定期执行安全测试")
            report.append("3. 保持安全更新")
        
        return '\n'.join(report)
    
    def run(self):
        """运行完整测试框架"""
        # 检查客户端是否存在
        if not os.path.exists(self.client_path):
            print(f"错误: 客户端程序不存在: {self.client_path}")
            return False
        
        # 执行fuzz测试
        critical_count, high_count = self.run_fuzz_tests()
        
        # 生成详细报告
        report = self.generate_detailed_report()
        print("\n" + report)
        
        # 保存报告到文件
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f"pop3_security_report_{timestamp}.txt"
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"\n详细报告已保存到: {report_file}")
        except Exception as e:
            print(f"保存报告失败: {e}")
        
        # 返回严重问题数量
        return critical_count > 0

def main():
    parser = argparse.ArgumentParser(description='一体化POP3高级fuzz测试框架')
    parser.add_argument('-c', '--client', default='./pop3_fuzz_client_v2.exe', 
                       help='客户端程序路径')
    parser.add_argument('-i', '--iterations', type=int, default=10,
                       help='测试迭代次数')
    
    args = parser.parse_args()
    
    # 创建并运行测试框架
    framework = POP3FuzzFramework(args.client, args.iterations)
    has_critical_issues = framework.run()
    
    # 如果发现严重问题，返回非零退出码
    if has_critical_issues:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == '__main__':
    main()