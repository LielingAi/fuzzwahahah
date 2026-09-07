import collections
from ..fuzzable_block import FuzzableBlock
from ..pgraph.node import Node


class FileFormatMutator(FuzzableBlock, Node):
    def __init__(self, name=None, sections=None):
        FuzzableBlock.__init__(self, name=name, request=self)
        Node.__init__(self)
        self.label = name
        self.sections = sections or []
        self.section_stack = []
        self.callbacks = collections.defaultdict(list)
        self.names = {name: self}
        self._rendered = b""
        self._mutant_index = 0
        self.mutant = None

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = name

    @property
    def fuzzable(self):
        return True
    
    def add_section(self, section):
        """
        添加一个新部分到文件格式中。
        """
        section.context_path = self._generate_context_path(self.section_stack)
        section.format_mutator = self

        if section.qualified_name in self.names:
            raise Exception("SECTION NAME ALREADY EXISTS: %s" % section.qualified_name)

        self.names[section.qualified_name] = section

        if not self.section_stack:
            self.sections.append(section)
        else:
            self.section_stack[-1].add_subsection(section)

        if isinstance(section, FileSection):
            self.section_stack.append(section)

    def render(self):
        """
        渲染整个文件格式的结构。
        """
        if self.section_stack:
            raise Exception("UNCLOSED SECTION: %s" % self.section_stack[-1].qualified_name)

        return self._render_file_data()

    def _generate_context_path(self, section_stack):
        context_path = ".".join(x.name for x in section_stack)
        context_path = ".".join(filter(None, (self.name, context_path)))
        return context_path

    def _render_file_data(self):
        """
        渲染整个文件内容数据。
        """
        return b"".join(section.render() for section in self.sections)

    def mutate(self):
        """
        执行变异操作。
        """
        if self._mutant_index >= len(self.sections):
            raise Exception("All sections have been mutated")

        # 执行一个简单变异：改变当前变异部分的名字为大写
        current_section = self.sections[self._mutant_index]
        current_section.name = current_section.name.upper()
        
        self.mutant = current_section
        self._mutant_index += 1

    def reset_mutation(self):
        """
        重置变异状态。
        """
        self._mutant_index = 0
        self.mutant = None
        for section in self.sections:
            section.name = section.name.lower()

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, self.name)

# 示例小节类
class FileSection:
    def __init__(self, name):
        self.name = name
        self.subsections = []

    def add_subsection(self, section):
        self.subsections.append(section)

    def render(self):
        return b"Section: " + self.name.encode()

# 使用示例
if __name__ == "__main__":
    root = FileFormatMutator(name="root")
    section1 = FileSection(name="header")
    section2 = FileSection(name="body")

    root.add_section(section1)
    root.add_section(section2)

    print(root.render())  # 首次输出
    root.mutate()  # 执行一次变异
    print(root.render())  # 再次输出显示变异结果
    root.reset_mutation()  # 重置变异状态
    print(root.render())  # 输出恢复为最初状态
    