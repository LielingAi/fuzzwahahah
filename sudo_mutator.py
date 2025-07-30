# -*- coding: utf-8 -*-
from afl_sudo_seed_generator import seed_generator

last_output = ""
def init(seed):
    """
    Called once when AFLFuzz starts up. Used to seed our RNG.

    @type seed: int
    @param seed: A 32-bit random value
    """
    #random.seed(seed)
    pass


def deinit():
    pass


def fuzz(buf, add_buf, max_size):
    """
    这里就是实现编译逻辑的地方
    该函数是核心，每次 AFL++ 需要对输入做自定义变异时都会调用它。
    实现自己的变异逻辑：对 buf（输入数据）进行随机/结构化修改，生成一个变异后的结果返回
    Called per fuzzing iteration.

    @type buf: bytearray
    @param buf: The buffer that should be mutated.主输入数据，bytes 类型，需要你去变异。

    @type add_buf: bytearray
    @param add_buf: A second buffer that can be used as mutation source.可选的另一个输入数据（bytes），通常用于“splicing（拼接）”操作（也可以不用它）。

    @type max_size: int
    @param max_size: Maximum size of the mutated output. The mutation must not
        produce data larger than max_size.
        生成的变异输出的最大允许长度（int）。

    @rtype: bytearray
    @return: A new bytearray containing the mutated data
        返回一个新的 bytes 对象，包含变异后的数据。

    注意
        必须返回变异后的数据，不能修改原地的 buf。
        如果什么都不想变异，可以返回原数据或者空 bytes（返回 0 长度会被 AFL++ 认为此轮跳过）。
    """
    # ret = bytearray(100)
    global last_output
    _seed = seed_generator.generate_all_seeds_no_save(buf.decode('utf-8'), count=100)
    last_output = _seed[-1]
    # ret[:3] = random.choice(COMMANDS)
    return bytearray(_seed[-1], encoding='utf-8')


# Uncomment and implement the following methods if you want to use a custom
# trimming algorithm. See also the documentation for a better API description.

# def init_trim(buf):
#     '''
#     Called per trimming iteration.
#
#     @type buf: bytearray
#     @param buf: The buffer that should be trimmed.
#
#     @rtype: int
#     @return: The maximum number of trimming steps.
#     '''
#     global ...
#
#     # Initialize global variables
#
#     # Figure out how many trimming steps are possible.
#     # If this is not possible for your trimming, you can
#     # return 1 instead and always return 0 in post_trim
#     # until you are done (then you return 1).
#
#     return steps
#
# def trim():
#     '''
#     Called per trimming iteration.
#
#     @rtype: bytearray
#     @return: A new bytearray containing the trimmed data.
#     '''
#     global ...
#
#     # Implement the actual trimming here
#
#     return bytearray(...)
#
# def post_trim(success):
#     '''
#     Called after each trimming operation.
#
#     @type success: bool
#     @param success: Indicates if the last trim operation was successful.
#
#     @rtype: int
#     @return: The next trim index (0 to max number of steps) where max
#              number of steps indicates the trimming is done.
#     '''
#     global ...
#
#     if not success:
#         # Restore last known successful input, determine next index
#     else:
#         # Just determine the next index, based on what was successfully
#         # removed in the last step
#
#     return next_index
#
# def post_process(buf):
#     '''
#     Called just before the execution to write the test case in the format
#     expected by the target
#
#     @type buf: bytearray
#     @param buf: The buffer containing the test case to be executed
#
#     @rtype: bytearray
#     @return: The buffer containing the test case after
#     '''
#     return buf
# def post_run():
#     '''
#     Called after each time the execution of the target program by AFL++
#     '''
#     pass
#
# def havoc_mutation(buf, max_size):
#     '''
#     Perform a single custom mutation on a given input.
#
#     @type buf: bytearray
#     @param buf: The buffer that should be mutated.
#
#     @type max_size: int
#     @param max_size: Maximum size of the mutated output. The mutation must not
#         produce data larger than max_size.
#
#     @rtype: bytearray
#     @return: A new bytearray containing the mutated data
#     '''
#     return mutated_buf
#
# def havoc_mutation_probability():
#     '''
#     Called for each `havoc_mutation`. Return the probability (in percentage)
#     that `havoc_mutation` is called in havoc. Be default it is 6%.
#
#     @rtype: int
#     @return: The probability (0-100)
#     '''
#     return prob
#
# def queue_get(filename):
#     '''
#     Called at the beginning of each fuzz iteration to determine whether the
#     test case should be fuzzed
#
#     @type filename: str
#     @param filename: File name of the test case in the current queue entry
#
#     @rtype: bool
#     @return: Return True if the custom mutator decides to fuzz the test case,
#         and False otherwise
#     '''
#     return True
#

def queue_new_entry(filename_new_queue, filename_orig_queue):
    '''
    Called after adding a new test case to the queue

    @type filename_new_queue: str
    @param filename_new_queue: File name of the new queue entry
                                新加入队列的测试用例文件名

    @type filename_orig_queue: str
    @param filename_orig_queue: File name of the original queue entry
                                原始队列文件名
    '''
    # global counter_dict

    # counter_dict[filename_new_queue] = filename_orig_queue
    # return False
    pass


def introspection():
    global last_output
    seed_generator.save_seed(last_output, 'sudo', 'command')
    return f"last_output crashed! is save ai model updated!"
