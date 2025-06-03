import re
import os
import time
import json
from datetime import datetime
from functools import lru_cache
from threading import Lock

import flask
from flask import Flask, redirect, render_template, jsonify

from .. import exception

MAX_LOG_LINE_LEN = 1500

prefix = os.environ.get("FLASK_APP_PREFIX", "")

app = Flask(__name__, static_url_path=f"{prefix}")
app.session = None  # Initialize your session as needed

# 性能优化缓存
_performance_cache = {}
_cache_lock = Lock()
_cache_timeout = 30  # 30秒缓存超时


def _get_cached_data(cache_key, generator_func, timeout=None):
    """获取缓存数据或生成新数据"""
    if timeout is None:
        timeout = _cache_timeout

    current_time = time.time()

    with _cache_lock:
        # 检查缓存是否存在且未过期
        if cache_key in _performance_cache:
            cached_data, cache_time = _performance_cache[cache_key]
            if current_time - cache_time < timeout:
                return cached_data

        # 生成新数据并缓存
        new_data = generator_func()
        _performance_cache[cache_key] = (new_data, current_time)
        return new_data


def _clear_cache():
    """清除所有缓存"""
    with _cache_lock:
        _performance_cache.clear()


def commify(number):
    number = str(number)
    processing = 1
    regex = re.compile(r"^(-?\d+)(\d{3})")
    while processing:
        (number, processing) = regex.subn(r"\1,\2", number)
    return number


@app.route(f"{prefix}/togglepause")
def pause():
    # Flip our state
    app.session.is_paused = not app.session.is_paused
    return redirect(flask.url_for("index"))


@app.route(f"{prefix}/test-case/<int:crash_id>")
def test_case(crash_id):
    return render_template(
        "test-case.html",
        crashinfo=app.session.procmon_results.get(crash_id, None),
        test_case=app.session.test_case_data(crash_id),
    )


@app.route(f"{prefix}/api/current-test-case")
def current_test_case_update():
    data = {"index": app.session.total_mutant_index, "log_data": _get_log_data(app.session.total_mutant_index)}
    return flask.jsonify(data)


@app.route(f"{prefix}/api/test-case/<int:test_case_index>")
def api_test_case(test_case_index):
    data = {"index": test_case_index, "log_data": _get_log_data(test_case_id=test_case_index)}
    return flask.jsonify(data)


@app.route(f"{prefix}/api/optimization-stats")
def optimization_stats():
    """Get optimization statistics from current session."""
    stats = {}

    if app.session and hasattr(app.session, 'fuzz_node') and app.session.fuzz_node:
        # Try to get optimization stats from the current fuzz node
        try:
            if hasattr(app.session.fuzz_node, 'get_optimization_stats'):
                stats['current_node'] = app.session.fuzz_node.get_optimization_stats()

            # Get stats from primitives if available
            if hasattr(app.session.fuzz_node, '_fuzzable_requests'):
                primitive_stats = {}
                for req_name, req in app.session.fuzz_node._fuzzable_requests.items():
                    if hasattr(req, 'get_optimization_stats'):
                        primitive_stats[req_name] = req.get_optimization_stats()

                if primitive_stats:
                    stats['primitives'] = primitive_stats

        except Exception as e:
            stats['error'] = str(e)

    # Add session performance data
    if app.session:
        stats['session_performance'] = {
            'total_mutations': getattr(app.session, 'total_num_mutations', 0),
            'current_index': getattr(app.session, 'total_mutant_index', 0),
            'runtime': getattr(app.session, 'runtime', 0),
            'exec_speed': getattr(app.session, 'exec_speed', 0),
            'is_paused': getattr(app.session, 'is_paused', False),
            'timestamp': datetime.now().isoformat()
        }

    return jsonify(stats)


def _generate_performance_data():
    """生成性能数据（用于缓存）"""
    performance_data = {}

    try:
        # Import and test our optimized generators
        try:
            from boofuzz.primitives.string import String
            from boofuzz.primitives.random_data import RandomData
        except ImportError:
            # Fallback to standard boofuzz imports
            from boofuzz import String, RandomData

        # Test String performance
        start_time = time.time()
        string_gen = String(name="perf_test", default_value="test", max_len=100)
        mutations = list(string_gen.mutations("test"))[:50]  # Limit for performance
        string_time = time.time() - start_time

        performance_data['string'] = {
            'mutations_count': len(mutations),
            'generation_time': string_time,
            'mutations_per_second': len(mutations) / string_time if string_time > 0 else 0,
            'has_optimization_stats': hasattr(string_gen, 'get_optimization_stats')
        }

        if hasattr(string_gen, 'get_optimization_stats'):
            performance_data['string']['optimization_stats'] = string_gen.get_optimization_stats()

        # Test RandomData performance
        start_time = time.time()
        random_gen = RandomData(name="perf_test", min_length=5, max_length=50, max_mutations=20)
        mutations = list(random_gen.mutations(b"test"))
        random_time = time.time() - start_time

        performance_data['random_data'] = {
            'mutations_count': len(mutations),
            'generation_time': random_time,
            'mutations_per_second': len(mutations) / random_time if random_time > 0 else 0,
            'has_optimization_stats': hasattr(random_gen, 'get_optimization_stats')
        }

        if hasattr(random_gen, 'get_optimization_stats'):
            performance_data['random_data']['optimization_stats'] = random_gen.get_optimization_stats()

    except ImportError as e:
        performance_data['error'] = f"Could not import optimized generators: {e}"
    except Exception as e:
        performance_data['error'] = f"Performance test failed: {e}"

    return performance_data


@app.route(f"{prefix}/api/generator-performance")
def generator_performance():
    """Get performance data for different generator types (cached)."""
    # 使用缓存获取性能数据
    performance_data = _get_cached_data("generator_performance", _generate_performance_data, timeout=60)
    performance_data['timestamp'] = datetime.now().isoformat()
    performance_data['cached'] = True
    return jsonify(performance_data)


def _get_log_data(test_case_id):
    results = []
    try:
        case = app.session.test_case_data(test_case_id)
    except exception.BoofuzzNoSuchTestCase:
        return None
    if case is not None:
        results.append({"css_class": case.css_class, "log_line": case.html_log_line})
        for step in case.steps:
            line = step.html_log_line
            results.append({"css_class": step.css_class, "log_line": line})
    return results


@app.route(f"{prefix}/api/current-run")
def index_update():
    """获取当前运行状态（增强版，包含优化信息）"""
    data = {
        "session_info": {
            "is_paused": app.session.is_paused,
            "current_index": app.session.total_mutant_index,
            "num_mutations": app.session.total_num_mutations,
            "current_index_element": app.session.mutant_index if app.session is not None else None,
            "num_mutations_element": (
                app.session.fuzz_node.get_num_mutations() if app.session.fuzz_node is not None else None
            ),
            "current_element": app.session.fuzz_node.name if app.session.fuzz_node is not None else None,
            "current_test_case_name": app.session.current_test_case_name,
            "crashes": _crash_summary_info(),
            "runtime": app.session.runtime,
            "exec_speed": app.session.exec_speed,
        }
    }

    # 添加优化信息（如果可用）
    try:
        # 获取缓存的性能数据
        perf_data = _get_cached_data("generator_performance", _generate_performance_data, timeout=120)
        if perf_data and 'string' in perf_data:
            data["optimization_info"] = {
                "mutations_per_second": perf_data['string'].get('mutations_per_second', 0),
                "optimizations_active": perf_data['string'].get('has_optimization_stats', False),
                "last_updated": datetime.now().isoformat()
            }
    except Exception:
        # 如果获取优化信息失败，不影响主要功能
        pass

    return flask.jsonify(data)


@app.route(f"{prefix}/api/cache/clear")
def clear_performance_cache():
    """清除性能缓存"""
    _clear_cache()
    return jsonify({"status": "success", "message": "Performance cache cleared", "timestamp": datetime.now().isoformat()})


@app.route(f"{prefix}/api/cache/status")
def cache_status():
    """获取缓存状态"""
    with _cache_lock:
        cache_info = {
            "cache_entries": len(_performance_cache),
            "cache_keys": list(_performance_cache.keys()),
            "cache_timeout": _cache_timeout,
            "timestamp": datetime.now().isoformat()
        }
    return jsonify(cache_info)


# optimization页面已移除，功能已整合到主界面


@app.route(f"{prefix}/")
def index():
    crashes = _crash_summary_info()

    # which node (request) are we currently fuzzing.
    if app.session.fuzz_node is not None and app.session.fuzz_node.name:
        current_name = app.session.fuzz_node.name
    else:
        current_name = "[N/A]"

    # render sweet progress bars.
    if app.session.fuzz_node is not None:
        mutant_index = float(app.session.mutant_index)
        num_mutations = float(app.session.fuzz_node.get_num_mutations())

        try:
            progress_current = min(mutant_index / num_mutations, 1)
        except ZeroDivisionError:
            progress_current = 0
        num_bars = int(progress_current * 50)
        progress_current_bar = "[" + "=" * num_bars + "&nbsp;" * (50 - num_bars) + "]"
        progress_current = "%.3f%%" % (progress_current * 100)
    else:
        progress_current = 0
        progress_current_bar = ""
        mutant_index = 0
        num_mutations = 100  # TODO improve template instead of hard coding fake values

    total_mutant_index = float(app.session.total_mutant_index)
    total_num_mutations = app.session.total_num_mutations
    if total_num_mutations is None:
        progress_total = 0
    else:
        try:
            progress_total = min(total_mutant_index / total_num_mutations, 1)
        except ZeroDivisionError:
            progress_total = 0

    num_bars = int(progress_total * 50)
    progress_total_bar = "[" + "=" * num_bars + "&nbsp;" * (50 - num_bars) + "]"
    progress_total = "%.3f%%" % (progress_total * 100)

    state = {
        "session": app.session,
        "current_mutant_index": commify(int(mutant_index)),
        "current_name": current_name,
        "current_num_mutations": commify(int(num_mutations)),
        "progress_current": progress_current,
        "progress_current_bar": progress_current_bar,
        "progress_total": progress_total,
        "progress_total_bar": progress_total_bar,
        "total_mutant_index": commify(int(total_mutant_index)),
        "total_num_mutations": commify(int(total_num_mutations)) if total_num_mutations is not None else None,
    }

    return render_template("index.html", state=state, crashes=crashes)


def _crash_summary_info():
    crashes = []
    procmon_result_keys = list(app.session.monitor_results)
    procmon_result_keys.sort()
    for key in procmon_result_keys:
        val = app.session.monitor_results[key]
        status_bytes = "&nbsp;"

        if key in app.session.monitor_data:
            status_bytes = commify(app.session.netmon_results[key])

        crash = {"key": key, "reasons": val, "status_bytes": status_bytes}
        crashes.append(crash)
    return crashes
